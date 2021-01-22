Assignment_1_Part_2: Cryptanalysis of Hill Cipher

Moodle Submission File Name: 2019SIY7580_AMAN_BHARDWAJ_HILL_CIPHER_CRYPTANALYSIS.zip
Examples File: EXAMPLES_A1_PART2.txt

In case you do not get the desired output or face any issue in running the code. Please contact me at following:
		Phone: 9882305248
		Email: aman.bhardwaj.cse.iitd.ac.in
		
How to run:

0. Extract 2019SIY7580_AMAN_BHARDWAJ_HILL_CIPHER_CRYPTANALYSIS.zip
	This contains two files:
	a. 2019SIY7580_AMAN_BHARDWAJ_HILL_CIPHER_CRYPTANALYSIS.py
	b. encrypted_text.txt : To place the encrypted text for cryptanalysis

1. Open file 
	a. 2019SIY7580_AMAN_BHARDWAJ_HILL_CIPHER_CRYPTANALYSIS.py and copy all code to Jupyter notebook in one cell. And Run it (Recommended)
	b. OR you can directly run through command prompt. python 2019SIY7580_AMAN_BHARDWAJ_HILL_CIPHER_CRYPTANALYSIS.py (python3 in case version >= 3)
	
2. Instructions To Run code:  
	a. Copy and paste the cipher text for cryptanalysis in "encrypted_text.txt" in the same folder and Save it. (It should only contain a-z chars)
	   Test Cases with desired output could be found in EXAMPLES_A1_PART2.txt
	b. Now you run the code, you will be asked to input the name of encrypted text file: 
		write "encrypted_text.txt" then press ENTER.
	c. Next you will be asked to enter Cipher Key Length. (Eg. for 2*2 Matrix enter Key length = 4)
		Provide Key Length and press ENTER.
	d. you should get deciphered text. and Cracked Key Matrix for hill cipher.
	e. in case you get the following message.
		"ALERT:
		Could not find the key combination in this try
		or Key size is not what you thought
		or Encryption key might not be invertible.
		Try again"
		Please run the code a few more times for same configurations. This is because I have capped the number of attempts for cryptanalysis to 		5000. if key is not found for given attempts this Alert is generated. So please try a few more times.
		
	
	NOTE: You will have to run the 2019SIY7580_AMAN_BHARDWAJ_HILL_CIPHER_ENCRYPT_DECRYPT.py again for every crypt analysis
	