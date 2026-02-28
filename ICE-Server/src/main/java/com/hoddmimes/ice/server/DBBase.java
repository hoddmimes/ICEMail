package com.hoddmimes.ice.server;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

public interface DBBase
{
    public void connect();
    public void close();

    public boolean ifUserExists( String pUsername ) throws DBException;
    public JsonObject findUser( String pUsername ) throws DBException;
    public JsonArray findAllUsers() throws DBException;
    public JsonArray findUsers( String pFilter ) throws DBException;
    public JsonArray findAllUserCredentials() throws DBException;
    public void createUser( JsonObject pUserProfile ) throws DBException;
    public void deleteUser( String pUsername ) throws DBException;

    public void saveDecryptMessage( String uid, String encryptedBody, String sender ) throws DBException;
    public JsonObject findDecryptMessage( String uid ) throws DBException;
    public String findUserPublicKey( String username ) throws DBException;
}
