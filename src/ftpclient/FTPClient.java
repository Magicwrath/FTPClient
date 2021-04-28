package ftpclient;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom; 
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import static javax.swing.JOptionPane.ERROR_MESSAGE;
import javax.swing.text.BadLocationException;



/**
 *
 * @author pedja
 */
public class FTPClient extends javax.swing.JFrame {
    
    private ServerConfiguration serverConfiguration;
    
    //Stringovi koji predstavljaju sve zahteve koje klijent moze da posalje
    //Ti zahtevi su: diskonekcija, prikaz fajlova i razmena novog AES kljuca
    //U slucaju zahteva preuzimanja fajla, bice poslat naziv fajla i njegova ekstenzija
    //Zbog toga ne postoji fiksan request String, dok se REQ_SEND_FILE salje nakon sto
    //klijent primi informaciju o velicini fajla
    public static final String REQ_DISCONNECT = "Disconnect";
    public static final String REQ_NEW_AES_KEY = "SendingAESKey";
    public static final String REQ_SHOW_ALL_FILES = "RequestAllFiles";
    public static final String REQ_SHOW_PDF_FILES = "RequestPDFFiles";
    public static final String REQ_SHOW_JPG_FILES = "RequestJPGFiles";
    public static final String REQ_SHOW_TXT_FILES = "RequestTXTFiles";
    public static final String REQ_SEND_FILE = "SendFile";
    
    //response stringovi za uspesne razmene AES kljuca i IV
    public static final String RESP_AES_EXCHANGE_READY = "AcceptingAESKey"; //odgovor da je server spreman da primi AES kljuc
    public static final String RESP_RECIEVED_AES_KEY = "AESKeyRecieved";
    public static final String RESP_RECIEVED_IV = "InitializationVectorRecieved";
    public static final String RESP_WRONG_REQ = "WrongRequest";
    
    //socket, is i os se koriste u komunikaciji sa serverom
    private Socket socket;
    private InputStream is;
    private OutputStream os;
    
    //atributi koji se koriste za enkripciju/dekripciju
    private SecretKey secretKeyAES;
    private byte[] initializationVector;
    private PublicKey serverPublicKeyRSA;
    private Cipher AESCipher;
    private Cipher RSACipher;
    
    //atribut koji oznacava direktorijum gde korisnik cuva
    //primljene podatke
    private File saveDir;

    /*
    Getters and setters
    */
    public PublicKey getServerPublicKeyRSA() {
        return serverPublicKeyRSA;
    }

    public void setServerPublicKeyRSA(PublicKey serverPublicKeyRSA) {
        this.serverPublicKeyRSA = serverPublicKeyRSA;
    }

   
    public SecretKey getSecretKeyAES() {
        return secretKeyAES;
    }

    public void setSecretKeyAES(SecretKey secretKeyAES) {
        this.secretKeyAES = secretKeyAES;
    }
    
    //ovaj getter je bitan za bezbedno zatvaranje konekcije
    //u slucaju da korisnik klikne "exit" dugme na window
    //management sistemu
    public Socket getClientSocket() {
        return this.socket;
    }

    /**
     * Konstruktor FTPClient klase
     * @throws java.security.NoSuchAlgorithmException
     * @throws javax.crypto.NoSuchPaddingException
     */
    public FTPClient() {
        initComponents();
        serverConfiguration = new ServerConfiguration();
        serverConfiguration.setVisible(false);
        try {
            RSACipher = Cipher.getInstance("RSA");
            AESCipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(FTPClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(FTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }       
    }

    /**
     * Funkcija generise tajni kljuc za AES enkripciju
     * @return generisani AES SecretKey 
     */
    public SecretKey createAESKey() {
        //Koristite objekte SecureRandom i KeyGenerator klase
        SecureRandom secureRandom = new SecureRandom();
        KeyGenerator keyGen;
        SecretKey secretKey = null;
        
        try {
            keyGen = KeyGenerator.getInstance("AES");
            //postaviti duzinu kljuca na 128 bita
            keyGen.init(128, secureRandom);
            
            //generisi AES kljuc
            secretKey = keyGen.generateKey();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(FTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        //ako je povratna vrednost null, desila se greska pri generisanju AES kljuca
        return secretKey;
    }
    
    /**
     * Napravi inicijalizacioni vektor potreban za simetricnu enkripciju
     * i dodali ga atributu initializationVector
     */
    public void createInitializationVector()
    {
        //Koristite objekat SecureRandom klase da bi generisali inicijalizacioni vektor
        byte[] initVector = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(initVector);
        //postavite initializationVector kao referencu na generisani inicijalizacioni vektor
        this.initializationVector = initVector;
    }    
    
    /**
     * Na osnovu niza bajtova dobijenih od servera, napravi PublicKey za RSA
     * i dodeli ga atributu serverPublicRSAKey
     * @param keyBytes niz bajtova poslatih od strane servera
     */
    public void createServerPublicRSAKey(byte[] keyBytes){
        try {
            //Koristite klase X509EncodedKeySpec i KeyFactory kako biste iz keyBytes
            //generisali serverPublicRSAKey
            this.serverPublicKeyRSA = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyBytes));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            Logger.getLogger(FTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /**
     * Enkriptuj skriveni kljuc za AES (prethodno kreiran) koristeci javni kljuc
     * za RSA dobijen od servera i vrati ga kao niz bajtova, 
     * kako bi se mogli proslediti serveru
     * @return enkriptovan skriveni kljuc za AES, kao niz bajtova
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidKeyException 
     */
    public byte[] encryptKeyRSA() throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        //inicijalizuj RSACipher u modu Cipher.ENCRYPT_MODE koristeci publicKeyRSA
        RSACipher.init(Cipher.ENCRYPT_MODE, serverPublicKeyRSA);
        //vrati secretKeyAES enkriptovan pomocu RSACipher
        return RSACipher.doFinal(secretKeyAES.getEncoded());
    }    

    /**
     * Enkriptuj inicijalizacioni vektor za AES (prethodno kreiran) koristeci javni kljuc
     * za RSA dobijen od servera i vrati ga kao niz bajtova, kako bi se mogli proslediti serveru
     * Inicijalizacioni vektor bi se mogao slati i nekriptovan, ali kad vec imamo
     * javni RSA kljuc, koristicemo njega da kriptujemo i IV
     * @return enkriptovan inicijalizacioni vektor za AES, kao niz bajtova
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidKeyException 
     */
    
    public byte[] encryptInitializationVector() throws Exception{
        //inicijalizuj RSACipher u modu Cipher.ENCRYPT_MODE koristeci publicKeyRSA
        RSACipher.init(Cipher.ENCRYPT_MODE, serverPublicKeyRSA);
        //vrati initializationVector enkriptovan pomocu RSACipher
        return RSACipher.doFinal(initializationVector);
    }

    
    /**
     * Dekriptuje niz bajtova na ulazu koristeci skriveni AES kljuc
     * @param input niz bajtova koji su primljeni od servera 
     * @return dekriptovan niz bajtova (po potrebi morace se konvertovati u string)
     * @throws Exception 
     */
    public byte[] do_AESDecryption(byte[] input) throws Exception{        
        //Koristite objekat IvParameterSpec klase sa initializationVector atributom
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        
        //Inicijalizujte AESCipher u Cipher.DECRYPT_MODE modu sa secretKeyAES
        AESCipher.init(Cipher.DECRYPT_MODE, secretKeyAES, ivParameterSpec);
  
        //vrati dekriptovani ulaz koristeci prethodno inicijalizovan AESCipher
        return AESCipher.doFinal(input);
    }   
    
    /**
     * Enkriptuj ulazni niz bajtova koristeci skriveni AES kljuc
     * Kriptovani izlaz se salje serveru
     * @param input ulazni niz bajtova koji treba kriptovati
     * @return kriptovani izlaz spreman za slanje serveru
     * @throws Exception 
     */
    public byte[] do_AESEncryption(byte[] input) throws Exception{
        //Koristite instancu klase IvParameterSpec zajedno sa initializationVector atributom
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
  
        //inicijalizujte AESCipher u modu Cipher.ENCRYPT_MODE, zajedno sa secretKeyAES kljucem
        AESCipher.init(Cipher.ENCRYPT_MODE, secretKeyAES, ivParameterSpec);
  
        //vrati enkriptovani ulaz koristeci prethodno inicijalizovan AESCipher
        return AESCipher.doFinal(input);
    }
    
        /**
     * Prima niz bajtova od servera i dekriptuje ih koristeci tajni AES kljuc
     * @param numOfBytes Ocekivani broj bajtova. Ako nije poznat, prosledjuje se 0
     * @return dekriptovani niz bajtova
     */
    public byte[] receiveAndDecryptMessage(int numOfBytes){
        byte[] ret = null;
        try {
            //cekaj dok nesto ne stigne
            while (this.is.available() <= 0);
            //proveri duzinu pristiglog niza i napravi niz odgovarajuce duzine
            int len = (numOfBytes == 0 ? this.is.available() : numOfBytes);
            byte[] receivedBytes = new byte[len];
            
            int current = 0;
            int bytesRead = 0;
            //citaj InputStream, sve dok ne vrati -1 (kraj stream-ovanja)
            do {
                //citaj sa offset-om current
                bytesRead = this.is.read(receivedBytes, current, (receivedBytes.length - current));
                //System.out.println(bytesRead);
                //ako si uspesno iscitao bytesRead bajtova, azuriraj offset
                if(bytesRead >= 0)
                    current += bytesRead;
            } while(current != receivedBytes.length);
            
            //dekriptuj poruku koristeci tajni AES kljuc           
            ret = do_AESDecryption(receivedBytes);
        } catch (IOException ex) {
            Logger.getLogger(FTPClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(FTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        return ret;
    }
    
    /**
     * Kriptuje poruku i salje ka serveru. Prilikom slanja se koristi OutputStream 
     * kao izlazna konekcija ka serveru
     * @param plainMsg nekriptovana poruka koja treba da se salje
     */
    public void encryptAndSendMessage(byte[] plainMsg){
        byte[] encryptedMsg = null;
        try {
            encryptedMsg = do_AESEncryption(plainMsg);
        } catch (Exception ex) {
            Logger.getLogger(FTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        try {
            //posalji enkriptovanu poruku koristeci OutputStream os
            this.os.write(encryptedMsg);
        } catch (IOException ex) {
            Logger.getLogger(FTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /**
     * Metoda koja apstrahuje proces slanja zahteva ka serveru bez enkripcije
     */
    public void sendRequestString(String request) {
        try {
            this.os.write(request.getBytes());
        } catch (IOException ex) {
            Logger.getLogger(FTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /**
     * Metoda koja apstrahuje proces primanja odgovora od servera bez enkripcije
     */
    @SuppressWarnings("empty-statement")
    String recieveResponseString() {
        try {
            while(this.is.available() <= 0);
            int msgLen = this.is.available();
            byte[] recievedBytes = new byte[msgLen];
            this.is.read(recievedBytes);
            String response = new String(recievedBytes);
            
            return response;
        } catch (IOException ex) {
            Logger.getLogger(FTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return null; //salje se ako se desila greska
    }
    
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jMenuItem1 = new javax.swing.JMenuItem();
        jCheckBoxMenuItem1 = new javax.swing.JCheckBoxMenuItem();
        lDostupneDatoteke = new javax.swing.JLabel();
        spDatoteke = new javax.swing.JScrollPane();
        taDatoteke = new javax.swing.JTextArea();
        spSadrzajDatoteke = new javax.swing.JScrollPane();
        taSadrzajDatoteke = new javax.swing.JTextArea();
        lSadrzajDatoteke = new javax.swing.JLabel();
        cbTipoviDatoteka = new javax.swing.JComboBox<>();
        btnTraziDatoteke = new javax.swing.JButton();
        btnPreuzmiDatoteku = new javax.swing.JButton();
        lSacuvajNaPutanji = new javax.swing.JLabel();
        tfSacuvajNaPutanji = new javax.swing.JTextField();
        btnPretrazi = new javax.swing.JButton();
        btnKonekcija = new javax.swing.JButton();
        btnSaljiKljucIV = new javax.swing.JButton();
        btnPreuzmiKljuc = new javax.swing.JButton();
        btnDiskonekcija = new javax.swing.JButton();
        jMenuBar1 = new javax.swing.JMenuBar();
        mKonfiguracija = new javax.swing.JMenu();
        miServer = new javax.swing.JMenuItem();
        mOpcije = new javax.swing.JMenu();
        miPrikazDatoteke = new javax.swing.JCheckBoxMenuItem();
        miIzlaz = new javax.swing.JMenuItem();

        jMenuItem1.setText("jMenuItem1");

        jCheckBoxMenuItem1.setSelected(true);
        jCheckBoxMenuItem1.setText("jCheckBoxMenuItem1");

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("FTP klijent");

        lDostupneDatoteke.setText("Spisak dostupnih datoteka:");
        lDostupneDatoteke.setEnabled(false);

        taDatoteke.setEditable(false);
        taDatoteke.setColumns(20);
        taDatoteke.setRows(5);
        taDatoteke.setEnabled(false);
        taDatoteke.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                taDatotekeMouseClicked(evt);
            }
        });
        spDatoteke.setViewportView(taDatoteke);

        taSadrzajDatoteke.setColumns(20);
        taSadrzajDatoteke.setRows(5);
        taSadrzajDatoteke.setEnabled(false);
        spSadrzajDatoteke.setViewportView(taSadrzajDatoteke);

        lSadrzajDatoteke.setText("Sadrzaj primljene datoteke:");
        lSadrzajDatoteke.setEnabled(false);

        cbTipoviDatoteka.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "All", "txt", "pdf", "jpeg" }));
        cbTipoviDatoteka.setEnabled(false);

        btnTraziDatoteke.setText("Trazi");
        btnTraziDatoteke.setEnabled(false);
        btnTraziDatoteke.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnTraziDatotekeActionPerformed(evt);
            }
        });

        btnPreuzmiDatoteku.setText("Preuzmi datoteku");
        btnPreuzmiDatoteku.setEnabled(false);
        btnPreuzmiDatoteku.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnPreuzmiDatotekuActionPerformed(evt);
            }
        });

        lSacuvajNaPutanji.setText("Sacuvaj na putanji:");
        lSacuvajNaPutanji.setEnabled(false);

        tfSacuvajNaPutanji.setEnabled(false);

        btnPretrazi.setText("Pretrazi");
        btnPretrazi.setEnabled(false);
        btnPretrazi.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnPretraziActionPerformed(evt);
            }
        });

        btnKonekcija.setText("Konektuj se");
        btnKonekcija.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnKonekcijaActionPerformed(evt);
            }
        });

        btnSaljiKljucIV.setText("Salji AES kljuc");
        btnSaljiKljucIV.setEnabled(false);
        btnSaljiKljucIV.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnSaljiKljucIVActionPerformed(evt);
            }
        });

        btnPreuzmiKljuc.setText("Preuzmi RSA kljuc");
        btnPreuzmiKljuc.setEnabled(false);
        btnPreuzmiKljuc.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnPreuzmiKljucActionPerformed(evt);
            }
        });

        btnDiskonekcija.setText("Diskonektuj se");
        btnDiskonekcija.setEnabled(false);
        btnDiskonekcija.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnDiskonekcijaActionPerformed(evt);
            }
        });

        mKonfiguracija.setText("Konfiguracija");

        miServer.setText("Server");
        miServer.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                miServerActionPerformed(evt);
            }
        });
        mKonfiguracija.add(miServer);

        jMenuBar1.add(mKonfiguracija);

        mOpcije.setText("Opcije");

        miPrikazDatoteke.setText("Prikaz datoteke");
        miPrikazDatoteke.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                miPrikazDatotekeActionPerformed(evt);
            }
        });
        mOpcije.add(miPrikazDatoteke);

        miIzlaz.setText("Izlaz");
        miIzlaz.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                miIzlazActionPerformed(evt);
            }
        });
        mOpcije.add(miIzlaz);

        jMenuBar1.add(mOpcije);

        setJMenuBar(jMenuBar1);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(spDatoteke, javax.swing.GroupLayout.PREFERRED_SIZE, 271, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(lDostupneDatoteke))
                        .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                .addComponent(btnKonekcija)
                                .addComponent(btnTraziDatoteke, javax.swing.GroupLayout.PREFERRED_SIZE, 86, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                .addGroup(layout.createSequentialGroup()
                                    .addGap(18, 18, 18)
                                    .addComponent(btnPreuzmiDatoteku, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                .addGroup(layout.createSequentialGroup()
                                    .addGap(39, 39, 39)
                                    .addComponent(btnDiskonekcija)))))
                    .addComponent(cbTipoviDatoteka, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(spSadrzajDatoteke, javax.swing.GroupLayout.DEFAULT_SIZE, 454, Short.MAX_VALUE)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(lSacuvajNaPutanji)
                        .addGap(4, 4, 4)
                        .addComponent(tfSacuvajNaPutanji))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)
                        .addComponent(btnPretrazi, javax.swing.GroupLayout.PREFERRED_SIZE, 142, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(lSadrzajDatoteke)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(55, 55, 55)
                                .addComponent(btnPreuzmiKljuc)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(btnSaljiKljucIV)))
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(31, 31, 31)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(lDostupneDatoteke)
                    .addComponent(lSadrzajDatoteke))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(spSadrzajDatoteke, javax.swing.GroupLayout.DEFAULT_SIZE, 278, Short.MAX_VALUE)
                    .addComponent(spDatoteke))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(cbTipoviDatoteka, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(lSacuvajNaPutanji)
                    .addComponent(tfSacuvajNaPutanji, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btnTraziDatoteke)
                    .addComponent(btnPreuzmiDatoteku)
                    .addComponent(btnPretrazi))
                .addGap(34, 34, 34)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btnKonekcija)
                    .addComponent(btnSaljiKljucIV)
                    .addComponent(btnPreuzmiKljuc)
                    .addComponent(btnDiskonekcija))
                .addContainerGap(34, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void miServerActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_miServerActionPerformed
        // TODO add your handling code here:
        this.serverConfiguration.setIPAdresaServera("");
        this.serverConfiguration.setPortServera(0);
        this.serverConfiguration.resetTextFields();
        this.serverConfiguration.setVisible(true);
    }//GEN-LAST:event_miServerActionPerformed

    private void btnKonekcijaActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnKonekcijaActionPerformed
        // TODO add your handling code here:
        String serverIp = serverConfiguration.getIPAdresaServera();
        int serverPort = serverConfiguration.getPortServera();
        //proveriti da li su unete informacije o serveru
        //ako nisu, pomocu dijaloga uputiti korisnika na konfiguraciju
        if((serverIp == null) || (serverPort == 0)) {
            JOptionPane.showMessageDialog(this, "Nije podesen IP i port Servera!\nPodesiti u Konfiguracija -> Server");
        } else {
            try {
                //ako su dobro uneti podaci, kreiraj socket
                socket = new Socket(serverIp, serverPort);
                //dodeli is i os atributima stream-ove od socketa
                this.is = socket.getInputStream();
                this.os = socket.getOutputStream();
                //ucini dugme za RSA kljuc vidljivim
                btnPreuzmiKljuc.setEnabled(true);
           } catch (IOException ex) {
                Logger.getLogger(FTPClient.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }//GEN-LAST:event_btnKonekcijaActionPerformed

    private void taDatotekeMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_taDatotekeMouseClicked
        // TODO add your handling code here:
        int pos = this.taDatoteke.getCaretPosition();
        int linenum = -1;
        int startIndex = -1;
        int endIndex = -1;
        try {
            linenum = this.taDatoteke.getLineOfOffset(pos);
        } catch (BadLocationException ex) {
            Logger.getLogger(FTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        try {
            startIndex = this.taDatoteke.getLineStartOffset(linenum);
            endIndex = this.taDatoteke.getLineEndOffset(linenum);
        } catch (BadLocationException ex) {
            Logger.getLogger(FTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        this.taDatoteke.select(startIndex, endIndex-1);
        //selektovani tekst mozete proveriti ako uklonite komentar ispod
        //JOptionPane.showMessageDialog(this, "Selected text: " + this.taDatoteke.getSelectedText());
    }//GEN-LAST:event_taDatotekeMouseClicked

    @SuppressWarnings("empty-statement")
    private void btnPreuzmiKljucActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnPreuzmiKljucActionPerformed
        //Funkcija za preuzimanje javnog kljuca od servera
        try {
            while(this.is.available() <= 0);
            int keyLen = this.is.available();
            byte[] recievedBytes = new byte[keyLen];
            //ocitaj poslati javni RSA kljuc
            this.is.read(recievedBytes);
            //pretvori primljene bajtove u publicKey
            createServerPublicRSAKey(recievedBytes);
            //ucini dugme za slanje AES kljuca vidljivim
            btnSaljiKljucIV.setEnabled(true);
            btnPreuzmiKljuc.setEnabled(false);
        } catch (IOException ex) {
            Logger.getLogger(FTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_btnPreuzmiKljucActionPerformed

    @SuppressWarnings("empty-statement")
    private void btnSaljiKljucIVActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnSaljiKljucIVActionPerformed
        //kreiraj AES kljuc i inicijalizacioni vektor
        secretKeyAES = createAESKey();
        createInitializationVector();
        
        try {     
            //klijent salje serveru zahtev REQ_NEW_AES_KEY za razmenu AES kljuca
            sendRequestString(REQ_NEW_AES_KEY);
            
            //cekaj da server odobri zahtev, odnosno posalje 
            String confirmationMsg = recieveResponseString();
            
            if(confirmationMsg.equalsIgnoreCase(RESP_AES_EXCHANGE_READY)) {
                //server je prihvatio zahtev, nastavi sa slanjem kriptovanog
                //AES kljuca i IV
                //enkriptuj kljuc sa javnim RSA kljucem servera
                byte[] encryptedKeyAES = encryptKeyRSA();
                this.os.write(encryptedKeyAES);

                //sacekaj odgovor servera "AESKeyRecieved"
                confirmationMsg = recieveResponseString();
                
                if(confirmationMsg.equalsIgnoreCase(RESP_RECIEVED_AES_KEY)) {
                    //sad poslati inicijalizacioni vektor po istom principu
                    byte[] encryptedVector = encryptInitializationVector();
                    this.os.write(encryptedVector);

                    //sacekaj da server odgovori
                    confirmationMsg = recieveResponseString();
                    
                    if(!confirmationMsg.equals(RESP_RECIEVED_IV)) {
                        System.out.println("Warning! Server IV confirmation message is invalid!");
                    } else {
                        JOptionPane.showMessageDialog(this, "Uspesno razmenjen AES kljuc i IV");
                        //sada moze razmena fajlova da pocne
                        //treba omoguciti combo box za odabir tipa podataka
                        //kao i dugme trazi i text area za podatke
                        btnTraziDatoteke.setEnabled(true);
                        btnDiskonekcija.setEnabled(true);
                        cbTipoviDatoteka.setEnabled(true);
                        btnPretrazi.setEnabled(true);
                        taDatoteke.setEnabled(true);
                        lDostupneDatoteke.setEnabled(true);
                        tfSacuvajNaPutanji.setEnabled(true);
                        lSacuvajNaPutanji.setEnabled(true);
                    }
                } else {
                    System.out.println("Warning! Server AES confirmation message is invalid!");
                }
            } else {
                JOptionPane.showMessageDialog(this, "Server je odbio zahtev za slanje novog AES kljuca!", "Greska", ERROR_MESSAGE);
            }
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | IOException ex) {
            Logger.getLogger(FTPClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(FTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_btnSaljiKljucIVActionPerformed

    private void btnTraziDatotekeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnTraziDatotekeActionPerformed
        //u zavisnosti od tipa podatka izabranog u combo box-u
        //traziti od servera listu podataka izabranog tipa
        //(poslati jedan od REQ Stringova)
        int fileTypeIndex = cbTipoviDatoteka.getSelectedIndex(); //0-All, 1-PDF, 2-JPG, 3-TXT
        String request;
        switch(fileTypeIndex) {
            case 0:
                //All files
                request = REQ_SHOW_ALL_FILES;
                break;
            case 1:
                //TXT
                request = REQ_SHOW_TXT_FILES;
                break;
            case 2:
                //PDF
                request = REQ_SHOW_PDF_FILES;
                break;
            default:
                //JPG
                request = REQ_SHOW_JPG_FILES;
                break;
        }
        
        try {
            //posalji kriptovani zahtev
            encryptAndSendMessage(request.getBytes());
            
            //sacekaj odgovor od servera
            byte[] decryptedResponse = receiveAndDecryptMessage(0);
            //pretvori odgovor u String
            String response = new String(decryptedResponse);
            taDatoteke.setText(response);
            
            //dozvoli korisniku da preuzme datoteke
            btnPreuzmiDatoteku.setEnabled(true);
        } catch (Exception ex) {
            Logger.getLogger(FTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_btnTraziDatotekeActionPerformed

    private void btnPretraziActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnPretraziActionPerformed
        //Implementacija dugmeta "Pretrazi"
        //treba da pozove JFileChooser da bi klijent izabrao
        //direktorijum gde cuva podatke koje server posalje
        JFileChooser fileChooser = new JFileChooser();
        //postaviti da korisnik moze samo direktorijume za izabere
        fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        
        //otvori dijalog za biranje direktorijuma
        int resp = fileChooser.showOpenDialog(this);
                
        //proveri da li je uspesno izabran direktorijum
        if(resp == JFileChooser.APPROVE_OPTION) {
            //prikazi izabrani direktorijum u tfSacuvajNaPutanji
            tfSacuvajNaPutanji.setText(fileChooser.getSelectedFile().getAbsolutePath());
        } else {
            JOptionPane.showMessageDialog(this, "Morate izabrati direktorijum!");
        }
    }//GEN-LAST:event_btnPretraziActionPerformed

    private void btnPreuzmiDatotekuActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnPreuzmiDatotekuActionPerformed
        //Metoda koja implementira preuzimanje datoteke
        //Klijent salje serveru ime datoteke kao zahtev u kriptovanom formatu
        //ukoliko server nadje datoteku salje je, u suprotnom salje RESP_WRONG_REQ
        
        //prvo treba proveriti da li je korisnik izabrao putanju gde ce da sacuva
        //i da li je data putanja direktorijum
        this.saveDir = new File(tfSacuvajNaPutanji.getText());
        
        if(this.saveDir.isDirectory()) {
            //ako je korisnik izabrao direktorijum za cuvanje podataka
            //proveriti da li je izabrao datoteku koju ce preuzeti
            if(this.taDatoteke.getSelectedText() != null) {
                String fileName = this.taDatoteke.getSelectedText();
                BufferedOutputStream bos = null;
                
                //posalji serveru zahtev sa imenom fajla
                encryptAndSendMessage(fileName.getBytes());
                
                //cekaj odgovor od servera i dekriptuj ga
                byte[] fileSizeArray = receiveAndDecryptMessage(0);
                
                //proveri da li je server poslao RESP_WRONG_REQ
                //ili je ocekivani odgovor (velicina fajla u bajtovima)
                String resp = new String(fileSizeArray);
                if(!resp.equalsIgnoreCase(RESP_WRONG_REQ)) {
                    //napravi fajl u saveDir
                    String sep = System.getProperty("file.separator");
                    File saveFile = new File(saveDir.getAbsolutePath() + sep + fileName);
                    
                    //parsiraj velicinu fajla iz odgovora "resp"
                    int fileSize = Integer.parseInt(resp);
                    //treba dodati "padding" na ovu velicinu
                    //da bi velicina fajla bila deljiva sa 16
                    while(fileSize % 16 != 0)
                        ++fileSize;
                    
                    //posalji serveru da si spreman da primis podatak
                    encryptAndSendMessage(REQ_SEND_FILE.getBytes());
                    
                    //primi podatak od fileSize bajtova
                    byte[] fileByteArray = receiveAndDecryptMessage(fileSize);
                    
                    try {
                        //kreiraj BufferedOutputStream da upise bajtove u fajl
                        bos = new BufferedOutputStream(new FileOutputStream(saveFile), fileByteArray.length);
                        bos.write(fileByteArray, 0, fileByteArray.length);
                        bos.flush();
                        bos.close();
                        
                        JOptionPane.showMessageDialog(this, "Uspesno preuzet fajl!");
                                                
                        //ako je text area omogucen, ocisti sadrzaj pri svakom preuzimanju fajlova
                        if(taSadrzajDatoteke.isEnabled()) {
                            taSadrzajDatoteke.setText("");
                            //ako je fajl tekstualnog tipa, prikazi ga prozoru za sadrzaj datoteke ako
                            //je opcija omogucena
                            if(fileName.substring(fileName.length() - 3, fileName.length()).equals("txt")) {
                                //text area za prikaz sadrzaja je omogucen
                                //citaj txt fajl sa baferovanim citacem i ispisuj sadrzaj
                                //u text area
                                BufferedReader br = new BufferedReader(new FileReader(saveFile));
                                String currentLineString;
                                
                                while((currentLineString = br.readLine()) != null)
                                    taSadrzajDatoteke.append(currentLineString + '\n');
                            }
                        }
                    } catch (FileNotFoundException ex) {
                        Logger.getLogger(FTPClient.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (IOException ex) {
                        Logger.getLogger(FTPClient.class.getName()).log(Level.SEVERE, null, ex);
                    }        
                } else {
                    JOptionPane.showMessageDialog(this, "Server nije pronasao podatak!");
                }
            } else {
                JOptionPane.showMessageDialog(this, "Morate izabrati podatak koji zelite da preuzmete!");
            }
        } else {
            JOptionPane.showMessageDialog(this, "Niste izabrali direktorijum u kome cete sacuvati fajlove!\nKliknite na dugme \"Pretrazi\"");
        }
    }//GEN-LAST:event_btnPreuzmiDatotekuActionPerformed

    private void miPrikazDatotekeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_miPrikazDatotekeActionPerformed
        //Korisnik je promenio stanje menu item-a za prikaz datoteke
        boolean state = miPrikazDatoteke.getState();
        
        //promeni stanje text area za prikaz sadrzaja i labele
        //pritom ocisti stari sadrzaj iz text area
        taSadrzajDatoteke.setText("");
        taSadrzajDatoteke.setEnabled(state);
        lSadrzajDatoteke.setEnabled(state);
    }//GEN-LAST:event_miPrikazDatotekeActionPerformed

    private void btnDiskonekcijaActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnDiskonekcijaActionPerformed
        // Metoda koja implementira diskonekciju
        // Treba poslati serveru zahtev REQ_DISCONNECT
        encryptAndSendMessage(REQ_DISCONNECT.getBytes());
        
        //iskljuciti sve komponente servera, osim dugmeta za konekcije
        btnPretrazi.setEnabled(false);
        btnPreuzmiDatoteku.setEnabled(false);
        btnPreuzmiKljuc.setEnabled(false);
        btnTraziDatoteke.setEnabled(false);
        btnDiskonekcija.setEnabled(false);
        btnSaljiKljucIV.setEnabled(false);
        taDatoteke.setEnabled(false);
        tfSacuvajNaPutanji.setEnabled(false);
        cbTipoviDatoteka.setEnabled(false);
        
        //ocisti bilo kakav sadrzaj iz text area
        taDatoteke.setText("");
        taSadrzajDatoteke.setText("");
        
        //takodje ocisti putanju u kojoj se cuvaju podaci
        tfSacuvajNaPutanji.setText("");
        
        try {
            //zatvori socket-e
            this.socket.close();
            this.is.close();
            this.os.close();
        } catch (IOException ex) {
            Logger.getLogger(FTPClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_btnDiskonekcijaActionPerformed

    private void miIzlazActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_miIzlazActionPerformed
        // Ukoliko korisnik izabere menu item "Izlaz"
        // salje se REQ_DISCONNECT ka serveru ako je prethodno uspostavljena
        // konekcija
        if(this.socket != null) {
            //proveri da li je mozda korisnik prvo stisnuo "Diskonektuj se"
            //i zatvorio socket
            if(!this.socket.isClosed()) {
                sendRequestString(REQ_DISCONNECT);
                try {
                    this.socket.close();
                    this.is.close();
                    this.os.close();
                } catch (IOException ex) {
                    Logger.getLogger(FTPClient.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
        
        //zatvori prozor aplikacije
        System.exit(0);
    }//GEN-LAST:event_miIzlazActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(FTPClient.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(FTPClient.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(FTPClient.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(FTPClient.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        
        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                //new FTPClient().setVisible(true);
                FTPClient clientFrame = new FTPClient();
                
                //listener za window management sistem
                //konkretno sa @Override se opisuje funkcija
                //za pozivanje u slucaju izlaska iz programa
                clientFrame.addWindowListener(new java.awt.event.WindowAdapter() {
                    @Override
                    public void windowClosing(java.awt.event.WindowEvent windowEvent) {
                        //izvrsi bezbednu diskonekciju sa serverom ako je prethodno uspostavljena
                        //komunikacija
                        if(clientFrame.getClientSocket() != null) {
                            //socket nije null, znaci da je postojala komunikacija
                            if(!clientFrame.getClientSocket().isClosed()) {
                                //ako prethodno nije pozvan close() od socket-a
                                //(korisnik nije stisnuo "Diskonektuj se")
                                //posalji serveru REQ_DISCONNECT bez enkripcije i zatvori socket
                                try {
                                    clientFrame.sendRequestString(REQ_DISCONNECT);
                                    clientFrame.getClientSocket().close();
                                } catch (IOException ex) {
                                    Logger.getLogger(FTPClient.class.getName()).log(Level.SEVERE, null, ex);
                                }
                            }
                        }
                    }
                });
                clientFrame.setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnDiskonekcija;
    private javax.swing.JButton btnKonekcija;
    private javax.swing.JButton btnPretrazi;
    private javax.swing.JButton btnPreuzmiDatoteku;
    private javax.swing.JButton btnPreuzmiKljuc;
    private javax.swing.JButton btnSaljiKljucIV;
    private javax.swing.JButton btnTraziDatoteke;
    private javax.swing.JComboBox<String> cbTipoviDatoteka;
    private javax.swing.JCheckBoxMenuItem jCheckBoxMenuItem1;
    private javax.swing.JMenuBar jMenuBar1;
    private javax.swing.JMenuItem jMenuItem1;
    private javax.swing.JLabel lDostupneDatoteke;
    private javax.swing.JLabel lSacuvajNaPutanji;
    private javax.swing.JLabel lSadrzajDatoteke;
    private javax.swing.JMenu mKonfiguracija;
    private javax.swing.JMenu mOpcije;
    private javax.swing.JMenuItem miIzlaz;
    private javax.swing.JCheckBoxMenuItem miPrikazDatoteke;
    private javax.swing.JMenuItem miServer;
    private javax.swing.JScrollPane spDatoteke;
    private javax.swing.JScrollPane spSadrzajDatoteke;
    private javax.swing.JTextArea taDatoteke;
    private javax.swing.JTextArea taSadrzajDatoteke;
    private javax.swing.JTextField tfSacuvajNaPutanji;
    // End of variables declaration//GEN-END:variables
}
