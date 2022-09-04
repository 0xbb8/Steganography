import java.awt.*;

import javax.imageio.ImageIO;
import javax.swing.*;
import java.awt.event.*;
import java.awt.image.BufferedImage;
import java.awt.image.DataBufferByte;
import java.awt.image.WritableRaster;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.swing.border.*;
import javax.swing.filechooser.*;
import javax.swing.plaf.multi.MultiLabelUI;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
Program: Image Steganography - LSB Encoding/Decoding
jMFilename: Steganography.java
@author: © Sandesh Gautam (2019)
Course: BSc Computing Year 3
Module: CSY4010 Computing Dissertation
Project Supervisor: Sir Indra Basnet
@version: Image Steganography Version 1.1.0
*/

public class StegGUI extends JFrame implements ActionListener{
	
	// -------------------------------------------------- GUI Component Initialization ------------------------------------------------------
	
	JFrame gui;
	JTabbedPane tabs;
	JPanel encodeWorkPanel, decodeWorkPanel, aboutPanel, imgPanel;
	JTextField encMessage, saveFileName,  dcdMessage, decMsgFname;
	JPanel realImage, encodedImage;
	JButton importBtn, encryptBtn,encodeBtn, saveImgBtn, browseImgbtn, decodeBtn, decryptBtn, saveMsgbtn;
	Border RLBevel = BorderFactory.createCompoundBorder(BorderFactory.createRaisedBevelBorder(), BorderFactory.createLoweredBevelBorder());
	Border ERaised = BorderFactory.createEtchedBorder(EtchedBorder.RAISED);
	Border LBevel = BorderFactory.createLoweredBevelBorder();
	
	// -------------------------------------------------- GUI Component Initialization ------------------------------------------------------
	
	// Cryptography Components
	public Cipher cipher;
	private static String secretKey = null;
	private static String saltBae = "Mike-Papa-November-Sierra";
	public boolean encrypt = false;
	
	// -------------------------------------------------- File Browser Components -----------------------------------------------------------
	
	public String fPath, fName;
	public boolean encoding_Successful = false;
	public boolean decoding_Successful = false;
	JFileChooser fileBrowser;
	public File ogImg = null;
	public File encImg = null;
	
	// -------------------------------------------------- File Browser Components -----------------------------------------------------------
	
	public JLabel encJLbl, dcdJLbl;
	public BufferedImage img, myImage, renderedImage, encoded_image;
	
	public String message =  null;
	public String decodedMsg = null;
	
	public DataBufferByte buffer;
	
	// Constructor to initialize the GUI components.
	StegGUI()
	{
		// Creating the JFrame
		gui = new JFrame();
		gui.setTitle("Image Steganography - LSB Encoding/Decoding");
		gui.setLayout(new BorderLayout());
		gui.setSize(730, 430);
		gui.setResizable(false);
		gui.setLocationRelativeTo(null);
		setDefaultCloseOperation(EXIT_ON_CLOSE);
		
		encodeTab();
		decodeTab();
		aboutTab();
		
		tabs = new JTabbedPane();
		
		tabs.addTab("Encode", encodeWorkPanel);
		tabs.addTab("Decode", decodeWorkPanel);
		tabs.addTab("About", aboutPanel);
		gui.add(tabs);
		gui.setVisible(true);
	}
	
	public void encode_function()
	{
		try
		{
			myImage = ImageIO.read(ogImg);
			
			encoded_image = user_space(myImage);
			encoded_image= add_text(encoded_image,message);
		}
		catch (IOException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	// Using  AES Encryption.
	public static String encryption(String plain, String seckey)
	{
		byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		IvParameterSpec ivspec = new IvParameterSpec(iv);
		
		try
		{
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), saltBae.getBytes(), 65536, 256);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
			// Secret Key/Encryption Key is input from the user.
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
			return Base64.getEncoder().encodeToString(cipher.doFinal(plain.getBytes("UTF-8")));
			
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
		
		
		return plain;
	}
	//(Gupta, 2019)
	
	//Using AES decryption.
	public static String decryption(String ciphertext, String secKey)
	{
		byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		IvParameterSpec ivspec = new IvParameterSpec(iv);
		
		try
		{
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), saltBae.getBytes(), 65536, 256);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
			//Secret key / decryption key is input from the user.
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
			return new String(cipher.doFinal(Base64.getDecoder().decode(ciphertext)));
		}
		catch (Exception e)
		{
			JOptionPane.showMessageDialog(null, "Incorrect Decryption Key.", "Error", JOptionPane.ERROR_MESSAGE);
		}
		
		return ciphertext;
	} 
	//(Gupta, 2019)
	
	public void save_image()
	{
		setImage(encoded_image,new File(image_path(fPath,saveFileName.getText()+"-Stego-Image","png")),"png");
		JOptionPane.showMessageDialog(null,"Image file is saved.","Save", JOptionPane.INFORMATION_MESSAGE);
	}
	
	private String image_path(String path, String name, String ext)
	{
		return path + "/" + name + "." + ext;
	}
	
	public void decode_function()
	{
		byte[] decode;
		
		BufferedImage image;
		try
		{
			image = user_space(ImageIO.read(encImg));
			decode = decode_text(getByteData(image));
			decodedMsg = new String(decode);
			dcdMessage.setText(decodedMsg);
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		
	}
	
	private BufferedImage user_space(BufferedImage image)
	{
		BufferedImage myImage = new BufferedImage(image.getWidth(), image.getHeight(), BufferedImage.TYPE_3BYTE_BGR);
		Graphics2D graphics = myImage.createGraphics();
		graphics.drawRenderedImage(image, null);
		graphics.dispose();
		
		return image;
	}
	
	private BufferedImage add_text(BufferedImage image, String text)
	{		
		byte img[] = getByteData(myImage);
		byte msg[] = message.getBytes();
		byte len[] = bit_conversion(msg.length);
		
		encode_text(img,len,0); //0 first positioning
		encode_text(img,msg,32); // 32 bits of space used for length
		
		return image;
	}
	
	private byte[] bit_conversion(int i)
    {		
        //Using 4 bytes of space for length.

        byte byte3 = (byte)((i & 0xFF000000) >>> 24); //0

        byte byte2 = (byte)((i & 0x00FF0000) >>> 16); //0

        byte byte1 = (byte)((i & 0x0000FF00) >>> 8 ); //0

        byte byte0 = (byte)((i & 0x000000FF));

        // Message length integers cast into bytes.
        return(new byte[]{byte3,byte2,byte1,byte0});

    }
	
	private byte[] getByteData(BufferedImage image)
	{
		WritableRaster raster = image.getRaster();
		buffer = (DataBufferByte) raster.getDataBuffer();
		// Accessing the buffer of an image.
		return buffer.getData();
	}
	
	private byte[] encode_text(byte[] image, byte[] addition, int offset)
	{
		// Checks the data + offset will fit in the immage.
		if(addition.length + offset > image.length)
		{
			throw new IllegalArgumentException("File not long enough!");
		}
		// loops through each byte of addition array.
		for(int i=0; i<addition.length; ++i)
	 	{
			int add = addition[i];
			//loops through each bit of addition byte.
			for(int bit=7; bit>=0; --bit, ++offset)
			{
				//assigns a single bit to integer b, shifts by bit spaces AND 1
		   	 	int b = (add >>> bit) & 1;
		   	 	//changes the LSB of the image and replaces with bit of addition
		   	 	// [(Previous byte value) AND 11111110] OR addition bit to add
		   		image[offset] = (byte)((image[offset] & 0xFE) | b );
			}
		}
		return image;
	}
	//(Wilson, 2007)
	
	// Exporting Image files.
	private boolean setImage(BufferedImage image, File file, String ext)
	{
		try
		{
			file.delete();
			ImageIO.write(image, ext, file);
			return true;
		}
		catch (Exception e)
		{
			e.printStackTrace();
			JOptionPane.showMessageDialog(null, "File could not be Saved!!!", "Error !!!", JOptionPane.ERROR_MESSAGE);
			return false;
		}
	}
	
	// Decoding message from Stego-image
	private byte[] decode_text(byte[] image)
	{
		int length = 0;
		int offset = 32; // message length is stored in first 32 bits. Message starts after 32 bits.
		for(int i=0; i<32; ++i) // getting message length
		{
			length = (length << 1) | (image[i] & 1);
		}
		byte[] result = new byte[length];
		for(int b=0; b<result.length; ++b ) 
			//loop through image bytes where number of iteration = length of message
		{
			for(int i=0; i<8; ++i, ++offset)
			{
				result[b] = (byte)((result[b] << 1) | (image[offset] & 1)); 
				// collected LSB from image stored in an array. It is the message byte.
			}
		}
		return result;
	}
	//(Wilson, 2007)
	
	// GUI Components for the Encode tab
	public void encodeTab()
	{
		encodeWorkPanel = new JPanel();
		encodeWorkPanel.setBounds(15,15,470,700);
		encodeWorkPanel.setBackground(Color.LIGHT_GRAY);
		encodeWorkPanel.setBorder(RLBevel);
		encodeWorkPanel.setLayout(null);
		
		JLabel realImgLbl = new JLabel();
		realImgLbl.setText("Original Image");
		realImgLbl.setBorder(LBevel);
		realImgLbl.setBounds(379,15,80,19);
		
		realImage = new JPanel();
		realImage.setBounds(10,35,450,290);
		realImage.setBorder(ERaised);
		realImage.setBackground(Color.WHITE);
		realImage.setVisible(true);
		
		importBtn = new JButton("Import Image");
		importBtn.setBounds(10,328,110,30);
		importBtn.addActionListener(this);
		
		saveImgBtn = new JButton("Save Image");
		saveImgBtn.setBounds(130,328,110,30);
		saveImgBtn.addActionListener(this);
		
		JPanel funcWorkPanel = new JPanel();
		funcWorkPanel.setBounds(480,15,230,345);
		funcWorkPanel.setBorder(RLBevel);
		funcWorkPanel.setLayout(null);
		
		JLabel encTextLbl = new JLabel();
		encTextLbl.setText("Enter Message: ");
		encTextLbl.setBorder(LBevel);
		encTextLbl.setBounds(5,5,100,19);
		
		encMessage = new JTextField();
		encMessage.setBorder(ERaised);
		encMessage.setBounds(5,29,215,80);
		encMessage.setText(null);
		
		JLabel fnameLbl = new JLabel();
		fnameLbl.setText("Enter Filename: ");
		fnameLbl.setBorder(LBevel);
		fnameLbl.setBounds(5,116,100,19);
		
		saveFileName = new JTextField();
		saveFileName.setBorder(ERaised);
		saveFileName.setBounds(5,138,215,20);
		
		encodeBtn = new JButton("Encode Image");
		encodeBtn.setBounds(60,180,110,30);
		encodeBtn.setEnabled(false);
		encodeBtn.addActionListener(this);
		
		encryptBtn = new JButton("Encrypt Message");
		encryptBtn.setBounds(57,220,116,30);
		encryptBtn.setEnabled(false);
		encryptBtn.addActionListener(this);
		
		gui.add(encodeWorkPanel);
		encodeWorkPanel.add(realImgLbl);
		encodeWorkPanel.add(realImage);
		encodeWorkPanel.add(importBtn);
		encodeWorkPanel.add(saveImgBtn);
		encodeWorkPanel.add(funcWorkPanel);
		
		funcWorkPanel.add(encTextLbl);
		funcWorkPanel.add(encMessage);
		funcWorkPanel.add(fnameLbl);
		funcWorkPanel.add(saveFileName);
		funcWorkPanel.add(encodeBtn);
		funcWorkPanel.add(encryptBtn);
	}
	
	// GUI components for the decode tab.
	public void decodeTab()
	{
		decodeWorkPanel = new JPanel();
		decodeWorkPanel.setBounds(15,15,470,700);
		decodeWorkPanel.setBackground(Color.LIGHT_GRAY);
		decodeWorkPanel.setBorder(RLBevel);
		decodeWorkPanel.setLayout(null);
		
		JLabel encodedImgLbl = new JLabel();
		encodedImgLbl.setText("Encoded Image");
		encodedImgLbl.setBorder(LBevel);
		encodedImgLbl.setBounds(379,15,80,19);
		
		encodedImage = new JPanel();
		encodedImage.setBounds(10,35,450,290);
		realImage.setBorder(ERaised);
		realImage.setBackground(Color.WHITE);
		realImage.setVisible(true);
		
		browseImgbtn = new JButton("Browse Image");
		browseImgbtn.setBounds(10,328,110,30);
		browseImgbtn.addActionListener(this);
		
		saveMsgbtn = new JButton("Save Message");
		saveMsgbtn.setBounds(130,328,110,30);
		saveMsgbtn.addActionListener(this);
		
		JPanel funcWorkPanel = new JPanel();
		funcWorkPanel.setBounds(480,15,230,345);
		funcWorkPanel.setBorder(RLBevel);
		funcWorkPanel.setLayout(null);
		
		JLabel dcdMessageLbl = new JLabel();
		dcdMessageLbl.setText("Decoded Message: ");
		dcdMessageLbl.setBorder(LBevel);
		dcdMessageLbl.setBounds(5,5,100,19);
		
		dcdMessage = new JTextField();
		dcdMessage.setBorder(ERaised);
		dcdMessage.setBounds(5,29,215,80);
		
		JLabel encFnameLbl = new JLabel();
		encFnameLbl.setText("Enter Filename: ");
		encFnameLbl.setBorder(LBevel);
		encFnameLbl.setBounds(5,116,100,19);
		
		decMsgFname = new JTextField();
		decMsgFname.setBorder(ERaised);
		decMsgFname.setBounds(5,138,215,20);
		
		decodeBtn = new JButton("Decode Image");
		decodeBtn.setBounds(60,180,110,30);
		decodeBtn.setEnabled(false);
		decodeBtn.addActionListener(this);
		
		decryptBtn = new JButton("Decrypt Message");
		decryptBtn.setBounds(57,220,116,30);
		decryptBtn.setEnabled(false);
		decryptBtn.addActionListener(this);
		
		gui.add(decodeWorkPanel);
		decodeWorkPanel.add(encodedImgLbl);
		decodeWorkPanel.add(encodedImage);
		decodeWorkPanel.add(saveMsgbtn);
		decodeWorkPanel.add(browseImgbtn);
		decodeWorkPanel.add(funcWorkPanel);
		
		funcWorkPanel.add(dcdMessageLbl);
		funcWorkPanel.add(dcdMessage);
		funcWorkPanel.add(encFnameLbl);
		funcWorkPanel.add(decMsgFname);
		funcWorkPanel.add(decodeBtn);
		funcWorkPanel.add(decryptBtn);
	}
	
	// Placing Images in the panels.
	public void addEncodingImage()
	{
		try {
			BufferedImage image = ImageIO.read(ogImg);
			encJLbl = new JLabel(new ImageIcon(image));
			realImage.add(encJLbl);
			System.out.println("image added in encoded Image Panel.");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public void addEncodedImage()
	{
		try {
			BufferedImage image = ImageIO.read(encImg);
			dcdJLbl = new JLabel(new ImageIcon(image));
			encodedImage.add(dcdJLbl);
			System.out.println("image added in decoding Image Panel.");
		} catch (IOException e) {
			JOptionPane.showMessageDialog(null, "Image is not selected.", "Null File", JOptionPane.ERROR_MESSAGE);
		}
	}
	
	// Information about the applicaiton in the about tab.
	public void aboutTab()
	{
		aboutPanel = new JPanel();
		aboutPanel.setBounds(15,15,470,700);
		aboutPanel.setBorder(RLBevel);
		aboutPanel.setLayout(null);
		
		JPanel displayPanel = new JPanel();
		displayPanel.setBorder(new EmptyBorder(70, 60, 0, 0));
		displayPanel.setBounds(20,20,680,335);
		
		JLabel aboutLbl = new JLabel();
		aboutLbl.setText("<html><body>"
				+ "*************************-*-*-*-    Image Steganography    -*-*-*-***************************"
				+ "<br>"
				+ "This java application is developed by Sandesh Gautam."
				+ "<br>"
				+ "BSc Computing (Networking)"
				+ "<br>"
				+ "NAMI College"
				+ "<br>"
				+ "This application is a demonstration of secure communication through images."
				+ "<br>"
				+ "This is a test application for my dissertation project."
				+ "<br>"
				+ "This application should be used only for educational purposes."
				+ "<br>"
				+ "*******************************************************************************************"
				+ "<br>"
				+ "Program: Image Steganography - LSB Encoding/Decoding "
				+ "<br>"
				+ "Version: 1.3.0"
				+ "<br>"
				+ "Aurthor: Sandesh Gautam (17425103)"
				+ "<br>"
				+ "Copyright© 2019*" 
				+ "<br>"
				+ "*******************************************************************************************"
				+ "<br>"
				+ "</body></html>");
		
		aboutPanel.add(displayPanel);
		displayPanel.add(aboutLbl, BorderLayout.CENTER);
	}
	
	// File browser to select images PNG and JPG.
	public void fileBrowser()
	{
		fileBrowser = new JFileChooser();
		fileBrowser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
		fileBrowser.setCurrentDirectory(new File("."));
		fileBrowser.setFileFilter(new FileNameExtensionFilter("Image Files (PNG, JPG)", "png", "jpg"));
		
		if (fileBrowser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION)
		{
			File dir = fileBrowser.getSelectedFile();
			System.out.println("File Directory: " + dir);
			
			try
			{
				// Extracting the filename and the directory path to be used while saving the image or text message.
				String name = dir.getName();
				String path = dir.getPath();
				fPath = path.substring(0,path.length()-name.length()-1);
				fName = name.substring(0, name.length()-4);
				
			} catch (Exception e) {
				// TODO: handle exception
			}			
		}
		else
		{
			// Dialog box appears when file is no selected.
			JOptionPane.showMessageDialog(null,"No file selected for Encoding.\nEncoding Cancelled","Null File", JOptionPane.YES_OPTION);
		}
	}

	@Override
	public void actionPerformed(ActionEvent btnPress) {
		// TODO Auto-generated method stub
		
		if (btnPress.getSource() == importBtn)
		{
			fileBrowser();
			ogImg = fileBrowser.getSelectedFile();
			if (ogImg != null)
			{
				addEncodingImage();
				JOptionPane.showMessageDialog(null,"File Selected for Message Encoding.","File Selected", JOptionPane.INFORMATION_MESSAGE);
				encodeBtn.setEnabled(true);
				encryptBtn.setEnabled(true);
			}
		}
		
		if (btnPress.getSource() == saveImgBtn)
		{
			if (encoding_Successful == false)
			{
				JOptionPane.showMessageDialog(null, "Image is not encoded yet.", "Not Encoded", JOptionPane.ERROR_MESSAGE);
			}
			else
			{
				if (saveFileName.getText().equals(""))
				{
					JOptionPane.showMessageDialog(null, "Encoded image filename is null.\nPlease enter a filename.", "!!! Null Filename !!!", JOptionPane.ERROR_MESSAGE);
				}
				else
				{
					save_image();
				}
			}
		}
		
		if (btnPress.getSource() == encryptBtn)
		{
			if (encMessage.getText().equals(""))
			{
				JOptionPane.showMessageDialog(null, "Message to be encoded is null.\nPlease enter a message.", "!!! Null Nessage !!!", JOptionPane.ERROR_MESSAGE);
			}
			else
			{
				encrypt = true;
				String enckey = JOptionPane.showInputDialog(null,"Enter Encryption Key:", "Encryption Key",JOptionPane.PLAIN_MESSAGE);
				secretKey = enckey;
			}
		}
		
		if (btnPress.getSource() == encodeBtn)
		{
			if (encMessage.getText().equals(""))
			{
				JOptionPane.showMessageDialog(null, "Message to be encoded is null.\nPlease enter a message.", "!!! Null Nessage !!!", JOptionPane.ERROR_MESSAGE);
			}
			else
			{
				message = encMessage.getText();
				if (encrypt == true)
				{
					message = encryption(message, secretKey);
					System.out.println("Message = " + message);
					encMessage.setText("");
					encMessage.setText(message);
				}
				encode_function();
				encoding_Successful = true;
				encrypt = false;
				JOptionPane.showMessageDialog(null,"Message is encoded in the Image.","Encoding Successful", JOptionPane.INFORMATION_MESSAGE);
			}
		}
		
		if (btnPress.getSource() == browseImgbtn)
		{
			fileBrowser();
			encImg = fileBrowser.getSelectedFile();
			if (encImg != null)
			{
				addEncodedImage();
				JOptionPane.showMessageDialog(null,"File Selected for Message Decoding.","File Selected", JOptionPane.INFORMATION_MESSAGE);
				decodeBtn.setEnabled(true);
				decryptBtn.setEnabled(true);
			}
		}
		
		if (btnPress.getSource() == decodeBtn)
		{
			if (encImg != null)
			{
				decode_function();
				decoding_Successful = true;
				JOptionPane.showMessageDialog(null,"Message is decoded from the Image.","Decoding Successful", JOptionPane.INFORMATION_MESSAGE);
			}
			else
			{
				JOptionPane.showMessageDialog(null,"No file selected for Decoding.\nDecoding Cancelled","Null File", JOptionPane.YES_OPTION);
			}
		}
		
		if (btnPress.getSource() == decryptBtn)
		{
			if (encImg != null)
			{
				String deckey = JOptionPane.showInputDialog(null,"Enter Decryption Key:", "Decryption Key",JOptionPane.PLAIN_MESSAGE);
				decodedMsg = decryption(decodedMsg, deckey);
				dcdMessage.setText(decodedMsg);
				System.out.println("Decoded Message: " + decodedMsg);
				JOptionPane.showMessageDialog(null,"Message is Decrypted.","Decryption Successful", JOptionPane.INFORMATION_MESSAGE);
			}
			else
			{
				JOptionPane.showMessageDialog(null,"No file selected for Decoding.\nDecoding Cancelled","Null File", JOptionPane.YES_OPTION);
			}
		}
		
		if (btnPress.getSource() == saveMsgbtn)
		{
			if (decoding_Successful == false)
			{
				JOptionPane.showMessageDialog(null, "Image is not decoded yet.", "Not Decoded", JOptionPane.ERROR_MESSAGE);
			}
			else
			{
				if (decMsgFname.getText().equals(""))
				{
					JOptionPane.showMessageDialog(null,"Filename for the text file is null.\nEnter a filename.","Null Filename", JOptionPane.INFORMATION_MESSAGE);
				}
				else
				{
					File textFile = new File(image_path(fPath,decMsgFname.getText()+"-decoded-message","txt"));
					String decodedMessage = dcdMessage.getText();
					
					try {
						FileOutputStream fileOut = new FileOutputStream(textFile);
						
						if (!textFile.exists())
						{
							textFile.createNewFile();
						}
						
						byte[] textContent = decodedMessage.getBytes();
						fileOut.write(textContent);
						fileOut.flush();
						fileOut.close();
						
						JOptionPane.showMessageDialog(null,"Text file export successful.","Save", JOptionPane.INFORMATION_MESSAGE);
						
					} catch (FileNotFoundException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			}
			
		}
		
	}
}
// Code references:
//Wilson, W. (2007) Steganography Dreamincode [Online] Available From: https://www.dreamincode.net/forums/topic/27950-steganography/ [Accessed Date: 24th December, 2018]
////Gupta, L. (2019) Java AES – 256 [Online] Available from: https://howtodoinjava.com/security/aes-256-encryption-decryption/ [Accessed Date: 28th April, 2019]
