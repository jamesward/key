package controllers;

import com.heroku.api.connection.HttpClientConnection;
import com.heroku.api.request.key.KeyAdd;
import com.heroku.api.request.login.BasicAuthLogin;
import com.heroku.api.response.Unit;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.KeyPair;

import play.mvc.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;


public class Application extends Controller {

    private static final String SSH_KEY_COMMENT = "key@heroku";
    private static final String SSH_KEY_FILE_NAME = "id_rsa_heroku";

    public static void index() {

        if ((request.headers.get("x-forwarded-proto") != null) && (request.headers.get("x-forwarded-proto").values.indexOf("https") != 0)) {
            redirect("https://" + request.host);
        }

        render();
    }

    public static void createKey(String username, String password, String publickey) throws JSchException, IOException {

        if ((request.headers.get("x-forwarded-proto") != null) && (request.headers.get("x-forwarded-proto").values.indexOf("https") != 0)) {
            index();
        }
        
        byte[] privateKeyByteArray = null;

        if (publickey.length() <= 0) {
            // create a new key pair
            JSch jsch = new JSch();
            KeyPair keyPair = KeyPair.genKeyPair(jsch, KeyPair.RSA);

            ByteArrayOutputStream privateKeyOutputStream = new ByteArrayOutputStream();
            keyPair.writePrivateKey(privateKeyOutputStream);
            privateKeyOutputStream.close();

            ByteArrayOutputStream publicKeyOutputStream = new ByteArrayOutputStream();
            keyPair.writePublicKey(publicKeyOutputStream, SSH_KEY_COMMENT);
            publicKeyOutputStream.close();

            publickey = new String(publicKeyOutputStream.toByteArray());

            privateKeyByteArray = privateKeyOutputStream.toByteArray();

        }

        HttpClientConnection herokuConnection = new HttpClientConnection(new BasicAuthLogin(username, password));

        KeyAdd keyAdd = new KeyAdd(publickey);
        Unit keyAddResponse = herokuConnection.execute(keyAdd);

        if (keyAddResponse == null) {
            throw new RuntimeException("Could not add an ssh key to the user");
        }

        if (privateKeyByteArray != null) {
            renderBinary(new ByteArrayInputStream(privateKeyByteArray), SSH_KEY_FILE_NAME);
        }

        flash("message", "Key added successfully!");
        index();
    }

}