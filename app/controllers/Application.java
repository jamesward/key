package controllers;

import com.heroku.api.HerokuAPI;
import com.heroku.api.connection.HttpClientConnection;
import com.heroku.api.request.key.KeyAdd;
import com.heroku.api.request.login.BasicAuthLogin;
import com.heroku.api.response.Unit;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.KeyPair;
import play.*;
import play.mvc.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.*;

import models.*;

public class Application extends Controller {

    private static final String SSH_KEY_COMMENT = "key@heroku";
    private static final String SSH_KEY_FILE_NAME = "id_rsa_heroku";

    public static void index() {
        render();
    }

    public static void createKey(String username, String password) throws JSchException, IOException {

        System.out.println("x-forwarded-proto " +  request.headers.get("x-forwarded-proto"));

        if ((request.headers.get("x-forwarded-proto") != null) && (request.headers.get("x-forwarded-proto").values.indexOf("https") != 0)) {
            redirect("https://" + request.host);
        }

        JSch jsch = new JSch();
        KeyPair keyPair = KeyPair.genKeyPair(jsch, KeyPair.RSA);

        ByteArrayOutputStream privateKeyOutputStream = new ByteArrayOutputStream();
        keyPair.writePrivateKey(privateKeyOutputStream);
        privateKeyOutputStream.close();

        ByteArrayOutputStream publicKeyOutputStream = new ByteArrayOutputStream();
        keyPair.writePublicKey(publicKeyOutputStream, SSH_KEY_COMMENT);
        publicKeyOutputStream.close();

        HttpClientConnection herokuConnection = new HttpClientConnection(new BasicAuthLogin(username, password));

        KeyAdd keyAdd = new KeyAdd(new String(publicKeyOutputStream.toByteArray()));
        Unit keyAddResponse = herokuConnection.execute(keyAdd);

        if (keyAddResponse == null) {
            throw new RuntimeException("Could not add an ssh key to the user");
        }

        renderBinary(new ByteArrayInputStream(privateKeyOutputStream.toByteArray()), SSH_KEY_FILE_NAME);
    }

}