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
    public void confirmUserByUsername( String pUsername ) throws DBException;
    public void updatePassword( String pUsername, String pNewHashedPassword, String pNewPrivateKey ) throws DBException;

    public int countProfiles() throws DBException;
    public int countActiveUsersLast24h() throws DBException;

    public void saveDecryptMessage( String uid, String encryptedBody, String sender, String attachmentsJson ) throws DBException;
    public JsonObject findDecryptMessage( String uid ) throws DBException;
    public int deleteExpiredDecryptMessages( int ttlHours ) throws DBException;
    public String findUserPublicKey( String username ) throws DBException;
}
