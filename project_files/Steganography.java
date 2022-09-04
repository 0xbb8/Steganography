import java.awt.*;
import javax.swing.*;
import java.awt.event.*;
import java.awt.image.BufferedImage;

import javax.swing.UIManager.LookAndFeelInfo;

/**
Program: Image Steganography Using LSB Programming
jMFilename: Steganography.java
@author: © Sandesh Gautam (2019)
Course: BSc Computing Year 3
Module: CSY4010 Computing Dissertation
Tutor: Sir Dipak Kumar Karna
Project Supervisor: Sir Indra Basnet
@version: Image Steganography Version 1.3.0
*/

//Use the test images in the folder 'stegtest'.

public class Steganography extends JFrame {
	
	// Just for the UI change.
	public static void main(String[] args)
	{
		
		try
		{
			UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		}
		catch(Exception e)
		{
			
		}
		
		StegGUI myGUI = new StegGUI();
	}
	
}
