'use strict';

const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

class SqliteHealthManager {
    constructor(options = {}) {
        this.Database = options.Database || Database;
        this.onConnectionRebound = options.onConnectionRebound || (() => {});
        this.logPrefix = options.logPrefix || 'KnowledgeBase';
        this.platform = options.platform || process.platform;
        // Darwin 对已映射的 -shm 被缩短会直接发出不可恢复的 SIGBUS。
        // PASSIVE checkpoint 是保守防线；根本防线是 rusqlite keepalive 与
        // better-sqlite3 候选连接提交共同保证两个 SQLite runtime 的读写
        // 连接引用在运行期不因“先关后开”而归零。
        // Linux 上 Rust rusqlite 与 better-sqlite3 双 SQLite runtime 共享同一
        // knowledge_base.sqlite：TRUNCATE checkpoint 会截断 WAL 文件，导致另一
        // runtime 已 mmap 的 WAL/-shm 页面失效，在 walFindFrame 触发不可恢复的
        // SIGBUS（与 macOS 同因）。因此全平台统一使用 PASSIVE checkpoint——
        // PASSIVE 只回写 WAL 不截断文件，避免 mmap 视图失效。
        this.checkpointMode = 'PASSIVE';
        const configuredBusyTimeout = Number(options.busyTimeoutMs);
        this.busyTimeoutMs = Number.isFinite(configuredBusyTimeout)
            ? Math.max(0, Math.floor(configuredBusyTimeout))
            : 10000;
        this.dbPath = null;
        this.db = null;
        this.state = 'healthy';
        this.corruptionDetected = false;
        this.recovering = false;
    }

    configureConnection(db) {
        db.pragma('journal_mode = WAL');
        db.pragma('synchronous = NORMAL');
        db.pragma('foreign_keys = ON');
        // Linux 上 Rust rusqlite 与 better-sqlite3 双 SQLite runtime 共享同一
        // knowledge_base.sqlite 的 WAL：Rust 侧 checkpoint/写 WAL 时，Node 侧
        // 已映射的 WAL 视图会失效，SQLite 在 walFindFrame 触发不可恢复的 SIGBUS。
        // 因此全平台关闭主数据库文件的可选 mmap（该设置不能替代两套 runtime 的
        // nRef 生命周期保护，WAL-index/SHM 仍由 SQLite 按协议管理）。
        db.pragma('mmap_size = 0');
        // 双 SQLite runtime 各自默认在 WAL 达 1000 页时自动 checkpoint（wal_autocheckpoint），
        // 任一方触发都会修改/重建 wal-index(-shm)，导致另一 runtime 已 mmap 的视图失效，
        // 在 walFindFrame 触发 SIGBUS。禁用两边的自动 checkpoint，改由 JS coordinator
        // 在低频屏障中显式执行 PASSIVE checkpoint（只回写不截断），消除周期踩踏。
        db.pragma('wal_autocheckpoint = 0');
        // SQLite 同一时刻只有一个写者。Rust/rusqlite、管理维护脚本或其他
        // better-sqlite3 连接短暂持锁时，在原生层等待锁释放，而不是立即把
        // 瞬态写竞争上抛成文件摄取失败。该配置属于连接级 PRAGMA，因此每次
        // 恢复/重开连接都必须重新设置。
        db.pragma(`busy_timeout = ${this.busyTimeoutMs}`);
    }

    assertIntegrity(db) {
        const row = db.prepare('PRAGMA quick_check').get();
        const result = row ? Object.values(row)[0] : 'ok';
        if (result !== 'ok') {
            const error = new Error(`SQLite quick_check failed: ${result}`);
            error.code = 'SQLITE_CORRUPT';
            throw error;
        }
    }

    checkpoint(db) {
        return db.pragma(`wal_checkpoint(${this.checkpointMode})`);
    }

    isCorruptionError(error) {
        const message = String(error?.message || error || '');
        return error?.code === 'SQLITE_CORRUPT'
            || error?.code === 'SQLITE_NOTADB'
            || /database disk image is malformed|file is not a database|database corruption|quick_check failed/i.test(message);
    }

    isBusyError(error) {
        const code = String(error?.code || '').toUpperCase();
        const message = String(error?.message || error || '');
        return code === 'SQLITE_BUSY'
            || code.startsWith('SQLITE_BUSY_')
            || code === 'SQLITE_LOCKED'
            || code.startsWith('SQLITE_LOCKED_')
            || /database (?:is )?locked|database table is locked/i.test(message);
    }

    openWithRecovery(dbPath) {
        this.dbPath = dbPath;
        let db = new this.Database(dbPath);
        try {
            this.configureConnection(db);
            this.assertIntegrity(db);
            this._publishConnection(db);
            return db;
        } catch (error) {
            if (!this.isCorruptionError(error)) {
                try { db.close(); } catch (_) {}
                throw error;
            }

            console.error(`[${this.logPrefix}] ❌ SQLite database corruption detected during startup.`);
            console.error(`[${this.logPrefix}] Corruption details: ${error.message || error}`);
            try { db.close(); } catch (_) {}

            const backupBase = this.quarantine(dbPath, 'startup-corrupt');
            console.warn(
                `[${this.logPrefix}] 🧯 Corrupt SQLite database quarantined as ` +
                `"${path.basename(backupBase)}*". A fresh database will be created and rebuilt from dailynote files.`
            );

            db = new this.Database(dbPath);
            this.configureConnection(db);
            this.assertIntegrity(db);
            this._publishConnection(db);
            return db;
        }
    }

    checkpointAndAssertHealthy(reason = 'manual-checkpoint') {
        if (!this.db) return false;
        try {
            this.checkpoint(this.db);
            this.assertIntegrity(this.db);
            this.state = 'healthy';
            return true;
        } catch (error) {
            if (!this.isCorruptionError(error)) {
                console.error(
                    `[${this.logPrefix}] 🚨 SQLite checkpoint/quick_check failed after ${reason}: ` +
                    `${error.message || error}`
                );
                return false;
            }

            console.warn(
                `[${this.logPrefix}] 🩺 SQLite checkpoint/quick_check reported suspect state after ` +
                `${reason}: ${error.message || error}`
            );
            this.state = 'suspect';
            return this.recoverSuspectConnection(reason, error);
        }
    }

    /**
     * Rust 使用独立 SQLite 运行时提交派生写后，长期存活的 better-sqlite3
     * 连接可能仍持有旧 pager/WAL/SHM read mark。候选连接先完成配置、
     * checkpoint 和 quick_check，发布成功后才关闭旧连接，确保本 runtime
     * 不出现会触发 readwrite first-attach 的 nRef 归零窗口。
     *
     * 该路径只用于低频 Rust 派生写屏障；普通 JS 写和手工健康检查仍复用现有连接。
     */
    reopenAndAssertHealthy(reason = 'rust-write-barrier') {
        // ⚠️ 不再物理重开 better-sqlite3 连接。实测证实（better-sqlite3 12.4.1）：
        // 任意连接的 close() 都会无条件删除 -shm/-wal（即使同 runtime 的其他
        // 连接仍存活；readonly 连接同样无法阻止）。而 Rust rusqlite keepalive
        // 与 riverMemoWorker worker 的 -shm mmap 无法感知该删除，下次访问
        // 即触发 walFindFrame SIGBUS（历史全部崩溃点）。
        // 改为在同一连接上执行 PASSIVE checkpoint + quick_check 完成写后验收；
        // Rust 侧写入的新帧经 WAL 协议的 mxFrame 检测自动可见，无需物理重连。
        return this.checkpointAndAssertHealthy(reason);
    }

    recoverSuspectConnection(reason, firstError) {
        // ⚠️ 与 reopenAndAssertHealthy 同理：不再物理重连。better-sqlite3
        // 任意连接 close() 都会无条件删除 -shm/-wal（readonly 亦如此），
        // 使 Rust keepalive 与 riverMemoWorker 的 -shm mmap 失效触发 SIGBUS。
        // suspect 状态下仅在同一连接上重试 checkpoint + quick_check；
        // 仍失败则保持连接存活（宁可继续可用，也不因重连删 -shm 崩溃）。
        if (!this.dbPath || this.recovering) return false;

        this.recovering = true;
        this.state = 'recovering';

        try {
            console.warn(
                `[${this.logPrefix}] 🩺 SQLite suspect state after ${reason}; ` +
                'retrying checkpoint + quick_check on the same connection (no reopen)...'
            );

            const healthy = this.checkpointAndAssertHealthy(`retry-after-${reason}`);
            if (healthy) {
                this.state = 'healthy';
                this.corruptionDetected = false;
                console.warn(
                    `[${this.logPrefix}] ✅ SQLite suspect recovered on same-connection retry after ${reason}; ` +
                    'treating as transient WAL/SHM view issue.'
                );
                return true;
            }

            // 仍失败：保持 suspect，不 close 不重连（避免删 -shm 导致 SIGBUS）。
            console.warn(
                `[${this.logPrefix}] 🩺 SQLite still suspect after ${reason}; ` +
                'keeping the live connection (physical reopen would delete -shm and crash the other SQLite runtime).'
            );
            return false;
        } finally {
            this.recovering = false;
        }
    }

    quarantine(dbPath, reason = 'corrupt') {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const backupBase = `${dbPath}.${reason}.${timestamp}.bak`;

        for (const file of [dbPath, `${dbPath}-wal`, `${dbPath}-shm`]) {
            if (!fs.existsSync(file)) continue;
            const suffix = file === dbPath
                ? ''
                : path.basename(file).slice(path.basename(dbPath).length);
            const target = `${backupBase}${suffix}`;
            try {
                fs.renameSync(file, target);
                console.warn(
                    `[${this.logPrefix}] 🧯 Quarantined "${path.basename(file)}" -> ` +
                    `"${path.basename(target)}"`
                );
            } catch (error) {
                console.error(
                    `[${this.logPrefix}] ❌ Failed to quarantine "${file}": ${error.message}`
                );
                throw error;
            }
        }
        return backupBase;
    }

    syncFromOwner(owner) {
        this.db = owner.db;
        this.dbPath = owner.dbPath;
        this.state = owner.dbHealthState;
        this.corruptionDetected = owner.databaseCorruptionDetected;
        this.recovering = owner._recoveringDatabaseConnection;
    }

    syncToOwner(owner) {
        owner.db = this.db;
        owner.dbPath = this.dbPath;
        owner.dbHealthState = this.state;
        owner.databaseCorruptionDetected = this.corruptionDetected;
        owner._recoveringDatabaseConnection = this.recovering;
    }

    _publishConnection(db) {
        this.db = db;
        this.onConnectionRebound(db);
    }
}

module.exports = SqliteHealthManager;