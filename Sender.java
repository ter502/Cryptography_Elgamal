import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.BufferedReader;
import java.io.FileReader;

public class Sender {
    public static void main(String[] args) {
        //input file path
        String inputFilePath = "./AsymmeticEncryption/test.txt";
        String inputFilePath2 = "./AsymmeticEncryption/mona_lisa_lowquality.jpg";
        String inputFilePath3 = "./AsymmeticEncryption/Lecture_08_RSAandElgamal.pdf";
        
        //output file path
        String encryptFilePath = "./AsymmeticEncryption/Encrypt/test_encrypt.txt";
        String encryptFilePath2 = "./AsymmeticEncryption/Encrypt/mona_lisa_lowquality_encrypt.jpg";
        String encryptFilePath3 = "./AsymmeticEncryption/Encrypt/Lecture_08_RSAandElgamal_encrypt.pdf";

        //Read Key File
        String PKFileB="./AsymmeticEncryption/KeyManagement/PublicKeyB.txt";
        BigInteger key[][]=readFile(PKFileB);

        //Read Prime Number
        BigInteger primeNumB = key[0][0];
        System.out.println("PrimeNum " + primeNumB);

        //Read Generator
        BigInteger generatorB = key[1][0];
        System.out.println("Generator " + generatorB);

        //Read Public Key
        BigInteger publicKeyB = key[2][0];
        System.out.println("PublicKey " + publicKeyB);


        System.out.println("======================================");

        Scanner sc = new Scanner(System.in);

        System.out.print("Enter n:");
        String N = sc.nextLine();
        int n = Integer.valueOf(N);
        
        System.out.println("======================================");

        //Calculate Number Range
        BigInteger start = nStart(n);
        BigInteger end = nEnd(n);
        System.out.println("Range = " + start + "~" + end);

        //Generate Prime Number
        BigInteger primeNumA = generateP(start, end);
        System.out.println("PrimeNum = " + primeNumA);

        //Create Generator
        BigInteger generatorA = generateG(primeNumA);
        System.out.println("Generator = " + generatorA);
        
        //Generate Private Key
        BigInteger privateKeyA = genPrivateKey(primeNumA);
        System.out.println("PrivateKey = " + privateKeyA);

        //Generate Public Key
        BigInteger publicKeyA = genPublicKey(primeNumA, generatorA, privateKeyA);
        System.out.println("PublicKey = " + publicKeyA);
        System.out.println("======================================");

        //Create Public Key File
        String PKFileA="./AsymmeticEncryption/KeyManagement/PublicKeyA.txt";
        createPublicFile(PKFileA, primeNumA, generatorA, publicKeyA);
        //public key(p,g,y)=(p,generator,pk)
        //private key(u)=privatekey
        
        try {
            //Convert file to byte array
            byte[] plain_bytes = Files.readAllBytes(Paths.get(inputFilePath));
            //Set Output Path
            FileOutputStream encrypFile = new FileOutputStream(encryptFilePath);
             //Encryption File
            byte[] encrypt_bytes = encryption(plain_bytes, primeNumB, generatorB, publicKeyB);
            encrypFile.write(encrypt_bytes);
            encrypFile.close();

            
            System.out.println("=====================sign===========================");

            BigInteger signed[]=signHash(primeNumA, generatorA, privateKeyA, plain_bytes);
            BigInteger r= signed[0];
            BigInteger s= signed[1];
            System.out.println("R : "+r);
            System.out.println("S : "+s);
            String signedFile="./AsymmeticEncryption/KeyManagement/Signature(r,s,X).txt";
            BigInteger plain = new BigInteger(plain_bytes);
            createSigHashFile(signedFile, r, s, plain);
            
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
    
    public static BigInteger[][] readFile(String path){
        // BigInteger setData[][]=new BigInteger[3][plainBytes.length];
        BigInteger setData[][]=null;
        
        try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
            String line;
            BigInteger r[] = null;
            BigInteger s[] = null;
            BigInteger X[] = null;
            List<BigInteger[]> dataList = new ArrayList<>();

            // Read the first line (r)
            if ((line = reader.readLine()) != null) {
                String[] values = line.split("\\s+"); // Split line by whitespace
                r = new BigInteger[values.length];
                for (int i = 0; i < values.length; i++) {
                    r[i] = new BigInteger(values[i]);
                }
                dataList.add(r);
                // r = new BigInteger(line);
                // setData[0]=r;
            }

            // Read the second line (s)
            if ((line = reader.readLine()) != null) {
                String[] values = line.split("\\s+"); // Split line by whitespace
                s = new BigInteger[values.length];
                for (int i = 0; i < values.length; i++) {
                    s[i] = new BigInteger(values[i]);
                }
                dataList.add(s);
                // s = new BigInteger(line);
                // setData[1]=s;
            }
            // Read the third line (s)
            if ((line = reader.readLine()) != null) {
                String[] values = line.split("\\s+"); // Split line by whitespace
                X = new BigInteger[values.length];
                for (int i = 0; i < values.length; i++) {
                    X[i] = new BigInteger(values[i]);
                }
                dataList.add(X);
                // X = new BigInteger(line);
                // setData[2]=X;
            }
            // Set the retrieved data into the setData array
            setData = new BigInteger[dataList.size()][];
            for (int i = 0; i < dataList.size(); i++) {
                setData[i] = dataList.get(i);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return setData;
    }

    public static void createPublicFile(String path, BigInteger p, BigInteger g, BigInteger y){
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(path))) {
            //write r on the first line
            writer.write(p.toString());
            writer.newLine(); // Move to the next line
            //write s on the next line
            writer.write(g.toString());
            writer.newLine();// Move to the next line
            writer.write(y.toString());

            System.out.println("Text file created successfully!");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void createSigHashFile(String path, BigInteger r, BigInteger s, BigInteger plainBytes){
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(path))) {
            //write r on the first line
            
            writer.write(r.toString());
            
            writer.newLine(); // Move to the next line
            //write s on the next line
            
            writer.write(s.toString());
            
            writer.newLine();// Move to the next line
            writer.write(plainBytes.toString());
            

            System.out.println("Text file created successfully!");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // Hash a byte array using SHA-256
    private static BigInteger hash(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(input);
            return new BigInteger(1, hashBytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    // x=secret key(sk)
    // y=public key(pk)
    // X=plaintext
    public static BigInteger[] signHash(BigInteger p,BigInteger g, BigInteger sk, byte[] plainBytes){
        BigInteger[] result = new BigInteger[3];
        BigInteger hash = hash(plainBytes).mod(p);
        System.out.println("Hash: " + hash);
        BigInteger K=generateK(p);
        BigInteger ink=K.modInverse(p.subtract(BigInteger.ONE));
        BigInteger r=modPow(g, K, p);
        BigInteger s=(ink.multiply(hash.subtract(sk.multiply(r)))).mod(p.subtract(BigInteger.ONE));
        result[0]=r;
        result[1]=s;
        result[2]=hash;
        return result;

    }
    public static boolean verify(BigInteger g, BigInteger pk, BigInteger X, BigInteger r, BigInteger s, BigInteger p){
        System.out.print("X : "+X+" ");
        BigInteger GpowX=modPow(g, X, p);
        System.out.print("GpowX = "+GpowX+" ");
        BigInteger yr=modPow(pk, r, p);
        BigInteger rs=modPow(r, s, p);
        BigInteger total=yr.multiply(rs).mod(p);
        System.out.print("Total = "+total+"  ");
        if(GpowX.equals(total)==true){
            System.out.print(" success ");
            System.out.println();
            return true;
        }else{
            System.out.print(" verify failed");
            System.out.println();
            return false;
        }
    }
}