package AsymmeticEncryption;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import javax.swing.text.Utilities;

public class Elgamal {
    public static void main(String[] args) throws ClassNotFoundException {
        //input file path
        String inputFilePath = "D:\\Lab\\src\\YearFour\\Cryptography\\AsymmeticEncryption\\test.txt";
        String inputFilePath2 = "D:\\Lab\\src\\YearFour\\Cryptography\\AsymmeticEncryption\\mona_lisa_lowquality.jpg";
        
        //output file path
        String outputFilePath = "D:\\Lab\\src\\YearFour\\Cryptography\\AsymmeticEncryption\\test_encryp.txt";
        String outputFilePath2 = "D:\\Lab\\src\\YearFour\\Cryptography\\AsymmeticEncryption\\picture_encryp.jpg";

        //decrypt path
        String decryptFilePath = "D:\\Lab\\src\\YearFour\\Cryptography\\AsymmeticEncryption\\test_decrypt.txt";
        String decryptFilePath2 = "D:\\Lab\\src\\YearFour\\Cryptography\\AsymmeticEncryption\\picture_decrypt.jpg";

        Scanner sc = new Scanner(System.in);

        System.out.print("Enter n:");
        int n = sc.nextInt();
        System.out.println("n is => " + n);

        BigInteger start = nStart(n);
        System.out.println("n start at " + start);

        BigInteger end = nEnd(n);
        System.out.println("n End at " + end);

        // isPrimeNumber(nEnd(n));
        System.out.println();
        BigInteger p = generateP(start, end);
        System.out.println("P " + p);

        BigInteger generator = generateG(p);
        System.out.println("G " + generator);

        BigInteger privatekey = genPrivateKey(p);
        System.out.println("K " + privatekey);

        BigInteger pk = genPublicKey(p, generator, privatekey);
        System.out.println("PK " + pk);
        
        // BigInteger bi = new BigInteger("-129");
        // byte[] biTest = bi.toByteArray();

        // for(byte b: biTest){
        //     System.out.println("-128: "+ b + "//");
        // }
        try {
            //Convert file to byte array
            byte[] plain_bytes = Files.readAllBytes(Paths.get(inputFilePath));
            //Set output path
            FileOutputStream output = new FileOutputStream(outputFilePath);
            FileOutputStream deOut = new FileOutputStream(decryptFilePath);


            System.out.println();

            //encryption file
            byte[] encrypt_bytes = encryption(plain_bytes, p, generator, pk);
            output.write(encrypt_bytes);

            //decryption file
            byte[] decrypt_bytes = Files.readAllBytes(Paths.get(outputFilePath));
            byte[] message_bytes = decryption(decrypt_bytes, p, privatekey);
            // for(byte m: message_byte){
            //     System.out.print(m);
            // }
            // System.out.println();
            // String msg = new String(message_byte);
            // System.out.println("msg = " + msg);
            deOut.write(message_bytes);
            output.close();
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
            System.out.println("value n is invaild!!");
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

        // if number is event return not prime number
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
        BigInteger p = BigInteger.ZERO;
        int len = end.bitLength();
        SecureRandom secureRandom = new SecureRandom();

        while(true){
            p = new BigInteger(len, secureRandom);
            // check prime number
            if(p.compareTo(start) >= 0 && isPrimeNumber(p) && p.compareTo(BigInteger.valueOf(255)) >= 0){
                break;
            } 
        }
        return p;
    }

    public static BigInteger generateG(BigInteger p){
        BigInteger g = BigInteger.ZERO;
        int len = p.bitLength();

        SecureRandom secureRandom = new SecureRandom();
        
        while(true){
            g = new BigInteger(len, secureRandom);
            // g > 1
            // g < p -1
            if(g.compareTo(BigInteger.ONE) > 0 && g.compareTo(p.subtract(BigInteger.ONE)) < 0){
                BigInteger l = modPow(g, (p.subtract(BigInteger.ONE)).divide(BigInteger.TWO), p); 
                BigInteger r = (p.subtract(BigInteger.ONE)).mod(p);
                // g^(p-1)/2 mod p = 1 mod p
                if(l.compareTo(r) == 0){
                    break;
                }
            }
        }
        return g;
    }

    public static BigInteger generateK(BigInteger p){
        BigInteger k = BigInteger.ZERO;
        int len = p.bitLength();

        SecureRandom secureRandom = new SecureRandom();
        
        while(true){
            k = new BigInteger(len, secureRandom);
            // g > 1
            // g < p -1
            if(k.compareTo(BigInteger.ONE) > 0 && k.compareTo(p.subtract(BigInteger.ONE)) < 0){
                BigInteger c = p.subtract(BigInteger.ONE);
                // gcd(k, p-1)
                if(findGCD(k, c).compareTo(BigInteger.ONE) == 0){
                    break;
                }
            }
        }
        return k;
    }

    public static BigInteger genPrivateKey(BigInteger p){
        BigInteger k = BigInteger.ZERO;
        int len = p.bitLength();

        SecureRandom secureRandom = new SecureRandom();
        
        while(true){
            k = new BigInteger(len, secureRandom);
            // k > 1
            // k < p -1
            if(k.compareTo(BigInteger.ONE) > 0 && k.compareTo(p.subtract(BigInteger.ONE)) < 0){
                break;
            }
        }
        return k;
    }

    public static BigInteger genPublicKey(BigInteger p, BigInteger g, BigInteger k){
        // y = g^k mod p
        BigInteger publicKey = modPow(g, k, p);

        if(publicKey.compareTo(BigInteger.ONE) < 0){
            System.out.println("Generate Public Key Fail !!");
        }
        return publicKey;
    }

    public static byte[] encryption(byte[] plain_bytes, BigInteger p, BigInteger g, BigInteger publicKey){
        List<Integer> cipherList = new ArrayList<Integer>();

        System.out.println("encryp");
        byte[] p_byteArray = p.toByteArray();
        System.out.println("p length = "+p_byteArray.length);

        for(byte pByte: plain_bytes){
            BigInteger k = generateK(p);
            BigInteger a = modPow(g, k, p);
            BigInteger y_pow_k = modPow(publicKey, k, p);

            // change a byte value to positive (byte range -128 to 127)
            // int A = Integer.valueOf(a.toString());
            // if(A < 0){
            //     A = 127 + (A * (-1));
            // }
            System.out.println(a+" ");
            byte[] a_array =  a.toByteArray();

            System.out.print("a block : ");
            //padding 0 to fill block p
            for(int padding = p_byteArray.length - a_array.length; padding > 0; padding--){
                System.out.print(0 + ", ");
                cipherList.add(0);
            }
            //fill a byte value
            for(int i = 0; i < a_array.length; i++){
                System.out.print(a_array[i] + ", ");
                cipherList.add((int)a_array[i]);
            }

            System.out.println();
            // tempList.add(Integer.valueOf(a.toString()));
            
            // change plain text byte value to positive (byte range -128 to 127)
            int x = (int)pByte;
            if(x < 0){
                x = 127 + (x * (-1));
            }
            // System.out.print(plain + " ");
            
            x = x % Integer.valueOf(p.toString());
            BigInteger b = (y_pow_k.multiply(BigInteger.valueOf(x))).mod(p);
            System.out.println(b + " ");
            byte[] b_array = b.toByteArray();
  
            System.out.print("b block : ");

            //padding 0 to fill block p
            for(int padding = p_byteArray.length - b_array.length; padding > 0; padding--){
                System.out.print(0 + ", ");
                cipherList.add(0);
            }
            //fill b byte value
            for(int i = 0; i < b_array.length; i++){
                System.out.print(b_array[i] + ", ");
                cipherList.add((int)b_array[i]);
            }
            System.out.println();

        }
        System.out.println();
        System.out.println("plain " + plain_bytes.length);
        for(int plan: plain_bytes){
            System.out.print(plan+ " ");
        }
        // System.out.println("\n-------------------------------------------------");

        // System.out.println("cipher " + cipherList.size());
        // for(int num: cipherList){
        //     System.out.print(num + " ");
        // }

        System.out.println("\n-------------------------------------------------");

        // byte[] cipher_byte = serialize(cipherList);
        System.out.println("Cipher byte[]");
        byte[] cipher_byte = new byte[cipherList.size()];
        for(int i = 0; i < cipher_byte.length; i++){
            int temp = cipherList.get(i);
            if(temp > 127 || temp <-128)System.out.println("encryption byte overflow !!");
            System.out.print((byte)temp + " ");
            cipher_byte[i] = (byte)temp;
            // System.out.println("cipher_byte[i] " + cipher_byte[i]);
        }
    
        System.out.println();
        // System.out.println("out ");
        // for(byte o: cipher_byte){
        //     System.out.print(o+" ");
        // }

        return cipher_byte;
    }

    public static byte[] decryption(byte[] cipher_bytes, BigInteger p, BigInteger privateKey){
        // byte[] arrayA = new byte[1];
        // byte[] arrayB = new byte[cipher_bytes.length - 1];
        System.out.println("decrypt");
        // ArrayList<Integer> cipherList = (ArrayList<Integer>)deserialize(cipher_bytes);
        System.out.println("cipher_bytes");
        for(byte cb: cipher_bytes){
            System.out.print(cb + " ");
        }
        System.out.println();
        List<Integer> plainList = new ArrayList<>();
        byte[] p_byteArray = p.toByteArray();
        System.out.println("p length = "+p_byteArray.length);
        
        // for(int i = 0; i < 1; i++){
        //     arrayA[i] = cipher_bytes[i];
        // }
        // for(int j = 1; j < cipher_bytes.length; j++){
        //     arrayB[j-1] = cipher_bytes[j];
        // }
        // BigInteger A = new BigInteger(arrayA);
        // System.out.println("\nA = " + A);
        // A = modPow(A, publicKey, p);
        
        
        for(int i = 0; i < cipher_bytes.length; i+=(p_byteArray.length * 2)){
            // System.out.println("p "+ p);
            byte[] a_array = new byte[p_byteArray.length];
            for(int j = 0; j < p_byteArray.length; j++){
                a_array[j] = cipher_bytes[i + j];
            }
            System.out.print("A array : ");
            for(byte b: a_array){
                System.out.print(b+" ");
            }
            System.out.println();
            BigInteger a = new BigInteger(a_array);
            System.out.println(a + " ");
            
            byte[] b_array = new byte[p_byteArray.length];
            for(int j = 0; j < p_byteArray.length; j++){
                b_array[j] = cipher_bytes[(i + p_byteArray.length) + j];
            }
            System.out.print("B array : ");
            for(byte b: b_array){
                System.out.print(b+" ");
            }
            System.out.println();
            BigInteger b = new BigInteger(b_array);
            System.out.println(b + " ");

            // System.out.println();
            // x = b / a;
            a = modPow(a, privateKey, p);
            a = a.modInverse(p);
            // System.out.println("a^-1 = "+a);
            BigInteger x = (b.multiply(a)).mod(p);
            int xTemp = Integer.valueOf(x.toString());
            System.out.print("x = "+x + " ");
            if(xTemp > 127){
                xTemp = -(xTemp - 127);
            }
            System.out.print("xTemp = "+xTemp + " ");
            
            System.out.println();
            // System.out.println("m = "+message);
            // System.out.println("=======================================");
            // System.out.println("x " +Integer.valueOf(x.toString()));
            plainList.add(xTemp);
            
            // change plain text range back (byte -128 to 127)
        }
        System.out.println();
        System.out.println("decrypt byte");
        byte[] plain_bytes = new byte[plainList.size()];
        for(int i = 0; i<plain_bytes.length; i++){
            plain_bytes[i] = plainList.get(i).byteValue();
            System.out.print(plain_bytes[i] + " ");
        }

        return plain_bytes;
    }
}
