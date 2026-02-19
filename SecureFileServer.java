/*
SecureFileTransfer.java

This file contains TWO Java programs in one file:
1) SecureFileServer
2) SecureFileClient

Run server first:
    java SecureFileServer 8000

Run client after:
    java SecureFileClient localhost 8000
*/

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/* ======================================================
   SecureFileServer — Runs on server side
====================================================== */
public class SecureFileServer {
    private final int port;
    private final KeyPair rsaKeyPair;
    private final ExecutorService pool = Executors.newCachedThreadPool();
    private final JFrame frame = new JFrame("Secure File Server");
    private final DefaultListModel<String> listModel = new DefaultListModel<>();

    public SecureFileServer(int port) throws Exception {
        this.port = port;
        this.rsaKeyPair = generateRSAKeyPair();
        setupGui();
    }

    private void setupGui() {
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(600, 400);

        JPanel p = new JPanel(new BorderLayout());
        JList<String> transfers = new JList<>(listModel);
        p.add(new JScrollPane(transfers), BorderLayout.CENTER);

        JButton clearBtn = new JButton("Clear List");
        clearBtn.addActionListener(e -> listModel.clear());
        p.add(clearBtn, BorderLayout.SOUTH);

        frame.getContentPane().add(p);
        frame.setVisible(true);
    }

    public void start() throws IOException {
        ServerSocket ss = new ServerSocket(port);
        System.out.println("SecureFileServer listening on port " + port);
        while (true) {
            Socket s = ss.accept();
            pool.submit(() -> handleClient(s));
        }
    }

    private void handleClient(Socket s) {
        String clientInfo = s.getInetAddress().getHostAddress() + ":" + s.getPort();
        SwingUtilities.invokeLater(() -> listModel.addElement("Connected: " + clientInfo));

        try (DataInputStream in = new DataInputStream(new BufferedInputStream(s.getInputStream()));
             DataOutputStream out = new DataOutputStream(s.getOutputStream())) {

            // 1 — Send RSA public key
            byte[] pub = rsaKeyPair.getPublic().getEncoded();
            out.writeInt(pub.length);
            out.write(pub);
            out.flush();

            // 2 — Receive encrypted AES key
            int encKeyLen = in.readInt();
            byte[] encKey = new byte[encKeyLen];
            in.readFully(encKey);

            byte[] aesKeyBytes = rsaDecrypt(encKey, rsaKeyPair.getPrivate());
            SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

            // 3 — Receive IV
            int ivLen = in.readInt();
            byte[] iv = new byte[ivLen];
            in.readFully(iv);

            // 4 — Receive filename
            int fnameLen = in.readInt();
            byte[] fnameBytes = new byte[fnameLen];
            in.readFully(fnameBytes);
            String filename = new String(fnameBytes, "UTF-8");

            // 5 — Receive encrypted file length + bytes
            long encFileLen = in.readLong();
            Path outEncPath = Path.of("received_" + filename + ".enc");

            try (OutputStream fileOut = Files.newOutputStream(outEncPath)) {
                byte[] buffer = new byte[8192];
                long remaining = encFileLen;
                while (remaining > 0) {
                    int toRead = (int) Math.min(buffer.length, remaining);
                    int read = in.read(buffer, 0, toRead);
                    if (read == -1) throw new EOFException("Unexpected EOF");
                    fileOut.write(buffer, 0, read);
                    remaining -= read;
                }
            }

            SwingUtilities.invokeLater(() ->
                    listModel.addElement("Saved encrypted file: " + outEncPath.toString()));

            // 6 — Decrypt file
            Path decPath = Path.of("decrypted_" + filename);
            decryptFileWithAES(aesKey, iv, outEncPath, decPath);

            SwingUtilities.invokeLater(() ->
                    listModel.addElement("Decrypted to: " + decPath.toString()));

            // 7 — Acknowledge
            out.writeBoolean(true);
            out.flush();

        } catch (Exception ex) {
            ex.printStackTrace();
            SwingUtilities.invokeLater(() ->
                    listModel.addElement("Error with " + clientInfo + ": " + ex.getMessage()));
        } finally {
            try { s.close(); } catch (IOException ignored) {}
        }
    }

    private static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static byte[] rsaDecrypt(byte[] data, PrivateKey priv) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        c.init(Cipher.DECRYPT_MODE, priv);
        return c.doFinal(data);
    }

    private static void decryptFileWithAES(SecretKey key, byte[] iv, Path encPath, Path outPath) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        try (InputStream fis = Files.newInputStream(encPath);
             CipherInputStream cis = new CipherInputStream(fis, cipher);
             OutputStream fos = Files.newOutputStream(outPath)) {
            byte[] buf = new byte[8192];
            int r;
            while ((r = cis.read(buf)) != -1) fos.write(buf, 0, r);
        }
    }

    public static void main(String[] args) throws Exception {
        int port = 8000;
        if (args.length > 0) port = Integer.parseInt(args[0]);
        SecureFileServer server = new SecureFileServer(port);
        server.start();
    }
}

/* ======================================================
   SecureFileClient — Runs on client system
====================================================== */
class SecureFileClient {
    private final String host;
    private final int port;
    private JFrame frame;
    private JProgressBar progressBar;
    private JTextArea logArea;

    public SecureFileClient(String host, int port) {
        this.host = host;
        this.port = port;
        SwingUtilities.invokeLater(this::buildGui);
    }

    private void buildGui() {
        frame = new JFrame("Secure File Client");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(600, 300);

        JPanel top = new JPanel();
        JButton chooseBtn = new JButton("Choose File and Send");
        chooseBtn.addActionListener(this::onChooseAndSend);
        top.add(chooseBtn);

        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);

        logArea = new JTextArea(8, 50);
        logArea.setEditable(false);

        frame.getContentPane().add(top, BorderLayout.NORTH);
        frame.getContentPane().add(progressBar, BorderLayout.CENTER);
        frame.getContentPane().add(new JScrollPane(logArea), BorderLayout.SOUTH);

        frame.setVisible(true);
    }

    private void onChooseAndSend(ActionEvent ev) {
        JFileChooser fc = new JFileChooser();
        int res = fc.showOpenDialog(frame);
        if (res != JFileChooser.APPROVE_OPTION) return;

        File f = fc.getSelectedFile();
        log("Selected: " + f.getAbsolutePath());

        new Thread(() -> {
            try {
                sendFile(f);
            } catch (Exception ex) {
                ex.printStackTrace();
                log("Error: " + ex.getMessage());
            }
        }).start();
    }

    private void log(String s) {
        SwingUtilities.invokeLater(() -> logArea.append(s + "\n"));
    }

    private void setProgress(double pct) {
        SwingUtilities.invokeLater(() -> progressBar.setValue((int) pct));
    }

    private void sendFile(File f) throws Exception {
        try (Socket s = new Socket(host, port);
             DataInputStream in = new DataInputStream(new BufferedInputStream(s.getInputStream()));
             DataOutputStream out = new DataOutputStream(s.getOutputStream())) {

            log("Connected to server " + host + ":" + port);

            // 1 — Read server public key
            int pubLen = in.readInt();
            byte[] pubBytes = new byte[pubLen];
            in.readFully(pubBytes);

            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey serverPub = kf.generatePublic(new X509EncodedKeySpec(pubBytes));
            log("Received server RSA public key");

            // 2 — Generate AES key + IV
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256);
            SecretKey aesKey = kg.generateKey();

            byte[] iv = new byte[16];
            SecureRandom sr = new SecureRandom();
            sr.nextBytes(iv);

            // 3 — Encrypt AES key using RSA
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, serverPub);
            byte[] encKey = rsaCipher.doFinal(aesKey.getEncoded());

            out.writeInt(encKey.length);
            out.write(encKey);

            out.writeInt(iv.length);
            out.write(iv);

            // 4 — Send filename
            byte[] nameBytes = f.getName().getBytes("UTF-8");
            out.writeInt(nameBytes.length);
            out.write(nameBytes);

            // 5 — Encrypt file to temp
            Path tmpEnc = Files.createTempFile("sft_tmp_", ".enc");
            long encSize = encryptFileToPath(aesKey, iv, f.toPath(), tmpEnc);
            out.writeLong(encSize);
            out.flush();

            // 6 — Stream encrypted file
            try (InputStream fis = Files.newInputStream(tmpEnc)) {
                byte[] buf = new byte[8192];
                long sent = 0;
                int r;
                while ((r = fis.read(buf)) != -1) {
                    out.write(buf, 0, r);
                    sent += r;
                    double pct = (encSize == 0) ? 100 : (100.0 * sent / encSize);
                    setProgress(pct);
                }
                out.flush();
            }

            boolean ack = in.readBoolean();
            if (ack) log("Server acknowledged receipt & decryption");
            else log("Server did NOT acknowledge");

            Files.deleteIfExists(tmpEnc);
            setProgress(100);
            log("Transfer completed.");
        }
    }

    private static long encryptFileToPath(SecretKey key, byte[] iv, Path inPath, Path outPath) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        try (InputStream fis = Files.newInputStream(inPath);
             OutputStream fos = Files.newOutputStream(outPath);
             CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {

            byte[] buf = new byte[8192];
            int r;
            while ((r = fis.read(buf)) != -1)
                cos.write(buf, 0, r);
        }

        return Files.size(outPath);
    }

    public static void main(String[] args) {
        String host = "localhost";
        int port = 8000;

        if (args.length >= 1) host = args[0];
        if (args.length >= 2) port = Integer.parseInt(args[1]);

        new SecureFileClient(host, port);
    }
}
