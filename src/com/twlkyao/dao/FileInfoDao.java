package com.twlkyao.dao;

import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteStatement;

import de.greenrobot.dao.AbstractDao;
import de.greenrobot.dao.Property;
import de.greenrobot.dao.internal.DaoConfig;

import com.twlkyao.dao.FileInfo;

// THIS CODE IS GENERATED BY greenDAO, DO NOT EDIT.
/** 
 * DAO for table FILE_INFO.
*/
public class FileInfoDao extends AbstractDao<FileInfo, Long> {

    public static final String TABLENAME = "FILE_INFO";

    /**
     * Properties of entity FileInfo.<br/>
     * Can be used for QueryBuilder and for referencing column names.
    */
    public static class Properties {
        public final static Property Id = new Property(0, Long.class, "id", true, "_id");
        public final static Property Md5 = new Property(1, String.class, "md5", false, "MD5");
        public final static Property Sha1 = new Property(2, String.class, "sha1", false, "SHA1");
        public final static Property Level = new Property(3, String.class, "level", false, "LEVEL");
    };


    public FileInfoDao(DaoConfig config) {
        super(config);
    }
    
    public FileInfoDao(DaoConfig config, DaoSession daoSession) {
        super(config, daoSession);
    }

    /** Creates the underlying database table. */
    public static void createTable(SQLiteDatabase db, boolean ifNotExists) {
        String constraint = ifNotExists? "IF NOT EXISTS ": "";
        db.execSQL("CREATE TABLE " + constraint + "'FILE_INFO' (" + //
                "'_id' INTEGER PRIMARY KEY AUTOINCREMENT ," + // 0: id
                "'MD5' TEXT UNIQUE ," + // 1: md5
                "'SHA1' TEXT UNIQUE ," + // 2: sha1
                "'LEVEL' TEXT);"); // 3: level
    }

    /** Drops the underlying database table. */
    public static void dropTable(SQLiteDatabase db, boolean ifExists) {
        String sql = "DROP TABLE " + (ifExists ? "IF EXISTS " : "") + "'FILE_INFO'";
        db.execSQL(sql);
    }

    /** @inheritdoc */
    @Override
    protected void bindValues(SQLiteStatement stmt, FileInfo entity) {
        stmt.clearBindings();
 
        Long id = entity.getId();
        if (id != null) {
            stmt.bindLong(1, id);
        }
 
        String md5 = entity.getMd5();
        if (md5 != null) {
            stmt.bindString(2, md5);
        }
 
        String sha1 = entity.getSha1();
        if (sha1 != null) {
            stmt.bindString(3, sha1);
        }
 
        String level = entity.getLevel();
        if (level != null) {
            stmt.bindString(4, level);
        }
    }

    /** @inheritdoc */
    @Override
    public Long readKey(Cursor cursor, int offset) {
        return cursor.isNull(offset + 0) ? null : cursor.getLong(offset + 0);
    }    

    /** @inheritdoc */
    @Override
    public FileInfo readEntity(Cursor cursor, int offset) {
        FileInfo entity = new FileInfo( //
            cursor.isNull(offset + 0) ? null : cursor.getLong(offset + 0), // id
            cursor.isNull(offset + 1) ? null : cursor.getString(offset + 1), // md5
            cursor.isNull(offset + 2) ? null : cursor.getString(offset + 2), // sha1
            cursor.isNull(offset + 3) ? null : cursor.getString(offset + 3) // level
        );
        return entity;
    }
     
    /** @inheritdoc */
    @Override
    public void readEntity(Cursor cursor, FileInfo entity, int offset) {
        entity.setId(cursor.isNull(offset + 0) ? null : cursor.getLong(offset + 0));
        entity.setMd5(cursor.isNull(offset + 1) ? null : cursor.getString(offset + 1));
        entity.setSha1(cursor.isNull(offset + 2) ? null : cursor.getString(offset + 2));
        entity.setLevel(cursor.isNull(offset + 3) ? null : cursor.getString(offset + 3));
     }
    
    /** @inheritdoc */
    @Override
    protected Long updateKeyAfterInsert(FileInfo entity, long rowId) {
        entity.setId(rowId);
        return rowId;
    }
    
    /** @inheritdoc */
    @Override
    public Long getKey(FileInfo entity) {
        if(entity != null) {
            return entity.getId();
        } else {
            return null;
        }
    }

    /** @inheritdoc */
    @Override    
    protected boolean isEntityUpdateable() {
        return true;
    }
    
}
