package com.twlkyao.dao;

// THIS CODE IS GENERATED BY greenDAO, DO NOT EDIT. Enable "keep" sections if you want to edit. 
/**
 * Entity mapped to table FILE_INFO.
 */
public class FileInfo {

    private Long id;
    private String md5;
    private String sha1;
    private String level;

    public FileInfo() {
    }

    public FileInfo(Long id) {
        this.id = id;
    }

    public FileInfo(Long id, String md5, String sha1, String level) {
        this.id = id;
        this.md5 = md5;
        this.sha1 = sha1;
        this.level = level;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getMd5() {
        return md5;
    }

    public void setMd5(String md5) {
        this.md5 = md5;
    }

    public String getSha1() {
        return sha1;
    }

    public void setSha1(String sha1) {
        this.sha1 = sha1;
    }

    public String getLevel() {
        return level;
    }

    public void setLevel(String level) {
        this.level = level;
    }

}