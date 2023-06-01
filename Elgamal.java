package AsymmeticEncryption;

import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Elgamal {
    public static void main(String[] args) {
        //input file path
        String inputFilePath = "D:\\Lab\\src\\YearFour\\Cryptography\\AsymmeticEncryption\\test.txt";
        String inputFilePath2 = "D:\\Lab\\src\\YearFour\\Cryptography\\AsymmeticEncryption\\mona_lisa_lowquality.jpg";
        String inputFilePath3 = "D:\\Lab\\src\\YearFour\\Cryptography\\AsymmeticEncryption\\Lecture_08_RSAandElgamal.pdf";
        
        //output file path
        String encryptFilePath = "D:\\Lab\\src\\YearFour\\Cryptography\\AsymmeticEncryption\\test_encrypt.txt";
        String encryptFilePath2 = "D:\\Lab\\src\\YearFour\\Cryptography\\AsymmeticEncryption\\mona_lisa_lowquality_encrypt.jpg";
        String encryptFilePath3 = "D:\\Lab\\src\\YearFour\\Cryptography\\AsymmeticEncryption\\Lecture_08_RSAandElgamal_encrypt.pdf";

        //decrypt path
        String decryptFilePath = "D:\\Lab\\src\\YearFour\\Cryptography\\AsymmeticEncryption\\test_decrypt.txt";
        String decryptFilePath2 = "D:\\Lab\\src\\YearFour\\Cryptography\\AsymmeticEncryption\\mona_lisa_lowquality_decrypt.jpg";
        String decryptFilePath3 = "D:\\Lab\\src\\YearFour\\Cryptography\\AsymmeticEncryption\\Lecture_08_RSAandElgamal_decrypt.pdf";

        Scanner sc = new Scanner(System.in);

        System.out.print("Enter n:");
        int n = sc.nextInt();
        
        System.out.println("======================================");

        //Calculate Number Range
        BigInteger start = nStart(n);
        BigInteger end = nEnd(n);
        System.out.println("Range = " + start + "~" + end);

        //Generate Prime Number
        BigInteger primeNum = generateP(start, end);
        System.out.println("PrimeNum = " + primeNum);

        //Create Generator
        BigInteger generator = generateG(primeNum);
        System.out.println("Generator = " + generator);

        //Generate Private Key
        BigInteger privateKey = genPrivateKey(primeNum);
        System.out.println("PrivateKey = " + privateKey);

        //Generate Public Key
        BigInteger publicKey = genPublicKey(primeNum, generator, privateKey);
        System.out.println("PublicKey = " + publicKey);

        System.out.println("======================================");
        
        try {
            //Convert Input File To Byte Array
            byte[] plain_bytes = Files.readAllBytes(Paths.get(inputFilePath3));

            //Set Output Path
            FileOutputStream encrypFile = new FileOutputStream(encryptFilePath3);
            FileOutputStream decryptFile = new FileOutputStream(decryptFilePath3);

            //Encryption File
            byte[] encrypt_bytes = encryption(plain_bytes, primeNum, generator, publicKey);
            encrypFile.write(encrypt_bytes);
            
            //Decryption File
            byte[] cipher_bytes = Files.readAllBytes(Paths.get(encryptFilePath3));
            byte[] message_bytes = decryption(cipher_bytes, primeNum, privateKey);
            decryptFile.write(message_bytes);

            encrypFile.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static BigInteger pow(BigInteger base, int n){
        BigInteger result = BigInteger.ONE;

        for(int i = 0; i < n; i++){
            result = result.multiply(base);
        }
        return result;
    }

    public static int pow(int base, int n){
        int result = 1;

        for(int i = 0; i < n; i++){
            result = result*base;
        }
        return result;
    }

    public static BigInteger pow(BigInteger base, BigInteger p){
        BigInteger result = BigInteger.ONE;

        for(BigInteger i = BigInteger.ZERO; i.compareTo(p) < 0; i = i.add(BigInteger.ONE)){
            result = result.multiply(base);
        }
        return result;
    }

    public static BigInteger modPow(BigInteger base, BigInteger p, BigInteger m){
        BigInteger result = BigInteger.ONE;
        base = base.mod(m);

        for(BigInteger i = BigInteger.ZERO; i.compareTo(p) < 0; i = i.add(BigInteger.ONE)){
            result = result.multiply(base);
            result = result.mod(m);
        }
        return result;
    }

    public static int modPow(int base, int p, int m){
        int result = 1;
        base = base % m;

        for(int i = 0; i < p; i++){
            result = result * base;
            result = result % m;
        }
        return result;
    }

    public static BigInteger findGCD(BigInteger number1, BigInteger number2){
        BigInteger gcd = BigInteger.ONE;

        for(BigInteger i = BigInteger.ONE; 
            i.compareTo(number1) <= 0 && i.compareTo(number2) <= 0;
            i = i.add(BigInteger.ONE))
        {   
            if(number1.mod(i).compareTo(BigInteger.ZERO) == 0 && number2.mod(i).compareTo(BigInteger.ZERO) == 0){
                gcd = i;
            }
        }
        return gcd;
    }
    
    public static BigInteger nStart(int n){
        if(n > 0){
            BigInteger s = pow(BigInteger.TWO, n-1);
            return s;
        }else{
            System.out.println("value n is invaild !!");
            return BigInteger.ZERO;
        }
    }

    public static BigInteger nEnd(int n){
        if(n > 0){
            BigInteger s = pow(BigInteger.TWO, n);
            return s.subtract(BigInteger.valueOf(1));
        }else{
            System.out.println("value n is invaild!!");
            return BigInteger.ZERO;
        }
    }

    public static boolean isPrimeNumber(BigInteger num){
        boolean isPrime = true;

        // If Number Is Event Return Not Prime Number
        if((num.mod(BigInteger.TWO)).compareTo(BigInteger.ZERO) == 0){
            isPrime = false;
            return isPrime;
        }

        for (BigInteger i = BigInteger.TWO; i.compareTo(num.divide(BigInteger.TWO)) <= 0; i = i.add(BigInteger.ONE)) {
          if (num.mod(i).equals(BigInteger.ZERO)) {
            isPrime = false;
            break;
          }
        }
        return isPrime;
    }

    public static BigInteger generateP(BigInteger start, BigInteger end){
        SecureRandom secureRandom = new SecureRandom();
        BigInteger p = BigInteger.ZERO;
        int len = end.bitLength();

        while(true){
            //Generate P
            p = new BigInteger(len, secureRandom);

            // Check Prime Number
            if(p.compareTo(start) >= 0 && isPrimeNumber(p) && p.compareTo(BigInteger.valueOf(255)) >= 0){
                break;
            }
        }
        return p;
    }

    public static BigInteger generateG(BigInteger p){
        SecureRandom secureRandom = new SecureRandom();
        BigInteger g = BigInteger.ZERO;
        int len = p.bitLength();

        while(true){
            //Generate G
            g = new BigInteger(len, secureRandom);

            //Generator Range =  1 < g < p-1
            if(g.compareTo(BigInteger.ONE) > 0 && g.compareTo(p.subtract(BigInteger.ONE)) < 0){
                // g^(p-1)/2
                BigInteger left = modPow(g, (p.subtract(BigInteger.ONE)).divide(BigInteger.TWO), p); 

                // 1 mod p
                BigInteger right = (p.subtract(BigInteger.ONE)).mod(p);
                
                //Check Is Generator g^(p-1)/2 mod p = 1 mod p
                if(left.compareTo(right) == 0){
                    break;
                }
            }
        }
        return g;
    }

    public static BigInteger generateK(BigInteger p){
        SecureRandom secureRandom = new SecureRandom();
        BigInteger k = BigInteger.ZERO;
        int len = p.bitLength();
        
        while(true){
            //Generate K
            k = new BigInteger(len, secureRandom);

            //Random Number K Range =  1 < k < p-1
            if(k.compareTo(BigInteger.ONE) > 0 && k.compareTo(p.subtract(BigInteger.ONE)) < 0){
                BigInteger c = p.subtract(BigInteger.ONE);

                //Check gcd(k, p-1)
                if(findGCD(k, c).compareTo(BigInteger.ONE) == 0){
                    break;
                }
            }
        }
        return k;
    }

    public static BigInteger genPrivateKey(BigInteger p){
        SecureRandom secureRandom = new SecureRandom();
        BigInteger k = BigInteger.ZERO;
        int len = p.bitLength();

        while(true){
            //Generate K
            k = new BigInteger(len, secureRandom);

            //Random Number K Range =  1 < k < p-1
            if(k.compareTo(BigInteger.ONE) > 0 && k.compareTo(p.subtract(BigInteger.ONE)) < 0){
                break;
            }
        }
        return k;
    }

    public static BigInteger genPublicKey(BigInteger primeNum, BigInteger generator, BigInteger k){
        // y = g^k mod p
        BigInteger publicKey = modPow(generator, k, primeNum);

        // If Public Key < 0 Show Fail Message
        if(publicKey.compareTo(BigInteger.ONE) < 0){
            System.out.println("Generate Public Key Fail !!");
        }
        return publicKey;
    }

    public static byte[] encryption(byte[] plain_bytes, BigInteger primeNum, BigInteger generator, BigInteger publicKey){
        System.out.println("Encryption Process ...");
        List<Integer> cipherList = new ArrayList<Integer>();
        byte[] prime_bytes = primeNum.toByteArray();

        for(byte plainByte: plain_bytes){
            //Generate Random Number K
            BigInteger k = generateK(primeNum);

            /* <----------------------------------------- a -----------------------------------------> */
            
            //Calculate a = g^k mod p
            BigInteger a = modPow(generator, k, primeNum);            
            
            //***** Convert a to bytes *****
            byte[] a_array =  a.toByteArray();

            //Padding 0 To Fill Empty Block In A Byte Array
            for(int padding = prime_bytes.length - a_array.length; padding > 0; padding--){
                cipherList.add(0);
            }
            //Fill A Bytes Value
            for(int i = 0; i < a_array.length; i++){
                cipherList.add((int)a_array[i]);
            }

            /* <---------------------------------------- (a) ----------------------------------------> */
            
            
            /* <----------------------------------------- b -----------------------------------------> */
            
            // Change Plain Text Byte Value To Positive 0 To 255 (Byte Range -128 to 127)
            int x = (int)plainByte;

            if(x < 0){
                x = 127 + (x * (-1));
            }
            
            //Calulate b = y^k * x mod p
            BigInteger y_pow_k = modPow(publicKey, k, primeNum);
            x = x % Integer.valueOf(primeNum.toString());
            BigInteger b = (y_pow_k.multiply(BigInteger.valueOf(x))).mod(primeNum);

            //***** Convert b to bytes *****
            byte[] b_array = b.toByteArray();

            //Padding 0 To Fill Empty Block In B Byte Array
            for(int padding = prime_bytes.length - b_array.length; padding > 0; padding--){
                cipherList.add(0);
            }
            //Fill B Bytes Value
            for(int i = 0; i < b_array.length; i++){
                cipherList.add((int)b_array[i]);
            }
            /* <---------------------------------------- (b) ----------------------------------------> */
        }

        // Add a And b in Cipher Bytes For Sending
        byte[] cipher_byte = new byte[cipherList.size()];

        for(int i = 0; i < cipher_byte.length; i++){
            //Get Byte Value
            int temp = cipherList.get(i);

            //Check Byte Value
            if(temp > 127 || temp <-128){
                System.out.println("Encryption Byte Value is Overflow !!");
                break;
            }
            cipher_byte[i] = (byte)temp;
        }

        System.out.println("<<< Encryption Finish >>>\n");
        return cipher_byte;
    }

    public static byte[] decryption(byte[] cipher_bytes, BigInteger primeNum, BigInteger privateKey){
        System.out.println("Decryption Process ...");
        List<Integer> plainList = new ArrayList<>();
        byte[] p_byteArray = primeNum.toByteArray();
        
        //Get a And b From Cipher Bytes
        for(int i = 0; i < cipher_bytes.length; i+=(p_byteArray.length * 2)){

            /* <----------------------------------------- a -----------------------------------------> */

            //Read Value a From Cipher Bytes
            byte[] a_array = new byte[p_byteArray.length];

            for(int j = 0; j < p_byteArray.length; j++){
                a_array[j] = cipher_bytes[i + j];
            }

            //Get a Value From a Bytes Array
            BigInteger a = new BigInteger(a_array);
            
            /* <---------------------------------------- (a) ----------------------------------------> */

            /* <----------------------------------------- b -----------------------------------------> */
            
            //Read Value b From Cipher Bytes
            byte[] b_array = new byte[p_byteArray.length];

            for(int j = 0; j < p_byteArray.length; j++){
                b_array[j] = cipher_bytes[(i + p_byteArray.length) + j];
            }

            //Get b Value From b Bytes Array
            BigInteger b = new BigInteger(b_array);

            /* <---------------------------------------- (b) ----------------------------------------> */

            /* <-------------------------------- Calulate Plain Text --------------------------------> */
            
            // a = a^u mod p
            a = modPow(a, privateKey, primeNum);

            // a = a^-1 mod p
            a = a.modInverse(primeNum);

            // x = b / a^u mod p
            BigInteger x = (b.multiply(a)).mod(primeNum);

            /* <------------------------------- (Calulate Plain Text) -------------------------------> */

            // Change Plain Text Byte Value Range Back -128 to 127
            int plainByte = Integer.valueOf(x.toString());

            if(plainByte > 127){
                plainByte = -(plainByte - 127);
            }

            //Add Plain Text Byte in Plain Text List
            plainList.add(plainByte);
            
        }

        // Add Plain Text Byte For Write It To File
        byte[] plain_bytes = new byte[plainList.size()];

        for(int i = 0; i < plain_bytes.length; i++){
            plain_bytes[i] = plainList.get(i).byteValue();
        }

        System.out.println("<<< Decryption Finish >>>\n");
        return plain_bytes;
    }
}
