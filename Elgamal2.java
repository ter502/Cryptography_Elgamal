import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
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

public class Elgamal2 {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        while(true){
            System.out.print("Command: ");
            String c = sc.nextLine();
            
            if(c.equalsIgnoreCase("generatekey")){
                //Get Key Size
                System.out.print("Key Size: ");
                String ks = sc.nextLine();
                int keySize = Integer.valueOf(ks);
                
                System.out.println("Key Generating ...");
                System.out.println("===================================================================");

                //Generate Prime Number
                BigInteger primeNum = generateP(keySize);
                System.out.println("Prime = " + primeNum);
                
                //Generate Generator
                BigInteger generator = generateG(primeNum);
                System.out.println("Generator = " + generator);

                //Generate Private Key
                BigInteger privateKey = genPrivateKey(primeNum);
                System.out.println("PrivateKey = " + privateKey);

                //Generate Public Key
                BigInteger publicKey = genPublicKey(primeNum, generator, privateKey);
                System.out.println("PublicKey = " + publicKey);

                System.out.println("===================================================================");

                //Creat Private Key File
                BigInteger tag = randomBigInt(BigInteger.valueOf(1000), BigInteger.valueOf(9999));
                String SKFileA="./AsymmeticEncryption/KeyManagement/privateKey_" + tag + ".txt";
                createPrivateFile(SKFileA, privateKey);

                //Creat Public Key File
                String SKFileB="./AsymmeticEncryption/KeyManagement/publicKey_" + tag + ".txt";
                createPublicFile(SKFileB, primeNum, generator, publicKey);

                System.out.println("<<<==================== Key Generate Finish ====================>>>");
            }

            if(c.equalsIgnoreCase("encryption")){
                //Read Public Key File
                System.out.print("Public Key File Path: ");
                String plainFilePath = sc.nextLine();

                //Set Output File Path
                System.out.print("Output File Path: ");
                String encryptFilePath = sc.nextLine();

                //Read Prime Number
                BigInteger primeNum = readFile(plainFilePath)[0][0];
                // System.out.println("Prime = " + primeNum);

                //Read Generator
                BigInteger generator = readFile(plainFilePath)[1][0];
                // System.out.println("Generator = " + generator);

                //Read Public Key
                BigInteger publicKey = readFile(plainFilePath)[2][0];
                // System.out.println("PublicKey = " + publicKey);


                //Get Plain Text File
                System.out.print("Plain Text File Path: ");
                String inputFilePath = sc.nextLine();

                System.out.println("Encryption Process ...");
                try {
                    byte[] plain_bytes = Files.readAllBytes(Paths.get(inputFilePath));
                    byte[] cipher_bytes = encryption(plain_bytes, primeNum, generator, publicKey);
                    FileOutputStream encrypFile = new FileOutputStream(encryptFilePath);
                    
                    //Create File Encryption
                    encrypFile.write(cipher_bytes);
                    encrypFile.close();
                }catch(IOException e){
                    e.printStackTrace();
                }
                System.out.println("<<< Encryption Finish >>>");
            }
            
            if(c.equalsIgnoreCase("decryption")){
                //Read Encryption File
                System.out.print("Encryption File Path: ");
                String encrypFilePath = sc.nextLine();

                //Set Output File Path
                System.out.print("Output File Path: ");
                String decryptFilePath = sc.nextLine();
                
                //Read Public Key File
                System.out.print("Public Key File Path: ");
                String publicFilePath = sc.nextLine();
                
                //Read Prime Number
                BigInteger primeNum = readFile(publicFilePath)[0][0];
                // System.out.println("Prime = " + primeNum);
                
                //Read Private Key File
                System.out.print("Private Key File Path: ");
                String privateFilePath = sc.nextLine();
                BigInteger privateKey = readFile(privateFilePath)[0][0];
                
                System.out.println("Decryption Process ...");
                try {
                    FileOutputStream decryptFile = new FileOutputStream(decryptFilePath);
                    byte[] cipher_bytes = Files.readAllBytes(Paths.get(encrypFilePath));
                    byte[] message_bytes = decryption(cipher_bytes, primeNum, privateKey);
                    decryptFile.write(message_bytes);
                    decryptFile.close();

                } catch (Exception e) {
                    e.printStackTrace();
                }
                System.out.println("<<< Decryption Finish >>>");
            }

            if(c.equalsIgnoreCase("signature")){
                //Read Public Key File
                System.out.print("Public Key File Path: ");
                String plainFilePath = sc.nextLine();

                //Read Prime Number
                BigInteger primeNum = readFile(plainFilePath)[0][0];
                // System.out.println("Prime = " + primeNum);

                //Read Generator
                BigInteger generator = readFile(plainFilePath)[1][0];
                // System.out.println("Generator = " + generator);

                //Read Private Key File
                System.out.print("Private Key File Path: ");
                String privateFilePath = sc.nextLine();
                BigInteger privateKey = readFile(privateFilePath)[0][0];

                //Get Plain Text File
                System.out.print("Plain Text File Path: ");
                String inputFilePath = sc.nextLine();

                System.out.println("Create Digital Signature ...");
                System.out.println("===================================================================");
                try {
                    byte[] plain_bytes = Files.readAllBytes(Paths.get(inputFilePath));
                    BigInteger signed[] = signHash(primeNum, generator, privateKey, plain_bytes);
                    BigInteger r = signed[0];
                    BigInteger s = signed[1];
                    BigInteger hash = signed[2];
                    System.out.println("R : "+r);
                    System.out.println("S : "+s);
                    System.out.println("===================================================================");
                    String hashFile = "./AsymmeticEncryption/KeyManagement/hash.txt";
                    createHashFile(hashFile, hash);
                    String signedFile = "./AsymmeticEncryption/KeyManagement/Signature.txt";
                    BigInteger plain = new BigInteger(plain_bytes);
                    createSigHashFile(signedFile, r, s, plain);
                }catch(IOException e){
                    e.printStackTrace();
                }
                System.out.println("<<< Digital Signature Create Finish >>>");
            }

            if(c.equalsIgnoreCase("verify")){
                System.out.println("Verifying ...");
                System.out.println("<<< Verify Finish >>>");
            }
            
            if(c.equalsIgnoreCase("exit"))
            {
                System.out.println("************ <<< Program Exit >>> ************");
                break;
            }
        }
    }

    public static int pow(int base, int n){
        int result = 1;

        for(int i = 0; i < n; i++){
            result = result*base;
        }
        return result;
    }

    public static BigInteger pow(BigInteger base, int n){
        BigInteger result = BigInteger.ONE;

        for(int i = 0; i < n; i++){
            result = result.multiply(base);
        }
        return result;
    }

    public static BigInteger fastExpo(BigInteger base, BigInteger power){
        BigInteger result = BigInteger.ONE;

        while (power.compareTo(BigInteger.ZERO) > 0) {
            if (power.testBit(0)) {
                result = result.multiply(base);
            }
            base = base.multiply(base);
            power = power.shiftRight(1);
        }

        return result;
    }

    public static BigInteger fastExpo(BigInteger base, BigInteger power, BigInteger modNum){
        BigInteger result = BigInteger.ONE;

        while (power.compareTo(BigInteger.ZERO) > 0) {
            if (power.testBit(0)) {
                result = result.multiply(base).mod(modNum);
            }
            base = base.multiply(base).mod(modNum);
            power = power.shiftRight(1);
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

    public static boolean isPrimeNumber(BigInteger num, int round){
        boolean isPrime = true;
        BigInteger a;
        BigInteger pow = (num.subtract(BigInteger.ONE)).divide(BigInteger.TWO);

        for(int i = 0; i < round; i++){
            a = randomBigInt(BigInteger.ONE, num.subtract(BigInteger.ONE));
            if(!fastExpo(a, pow, num).equals(BigInteger.ONE) && !fastExpo(a, pow, num).equals(num.subtract(BigInteger.ONE))){
                isPrime = false;
                break;
            }
        }

        return isPrime;
    }

    public static boolean isSafePrime(BigInteger num){
        BigInteger q = num.subtract(BigInteger.ONE).divide(BigInteger.TWO);
        return isPrimeNumber(q, 100);
    }

    public static BigInteger randomBigInt(BigInteger min, BigInteger max){
        SecureRandom secureRandom = new SecureRandom();
        int len = max.bitLength();
        BigInteger num = new BigInteger(len, secureRandom);

        while(true){
            if(num.compareTo(min) >= 0 && num.compareTo(max) < 0){
                break;
            }else{
                num = new BigInteger(len, secureRandom);
            }
        }

        return num;
    }

    public static BigInteger generateP(int keySize){
        BigInteger p = BigInteger.ZERO;
        BigInteger min = nStart(keySize);
        BigInteger max = nEnd(keySize);

        while(true){
            //Generate P
            p = randomBigInt(min, max);

            // Check Prime Number
            if(isPrimeNumber(p, 100) && isSafePrime(p)){
                if(p.compareTo(BigInteger.valueOf(255)) < 0){
                    System.out.println("n is too small for collect byte data !");
                }
                break;
            }
        }
        return p;
    }

    public static BigInteger generateG(BigInteger p){
        BigInteger g = BigInteger.ZERO;

        while(true){
            //Generate G
            g = randomBigInt(BigInteger.ONE, p);

            //Generator Range =  1 < g < p-1
            if(g.compareTo(BigInteger.ONE) > 0 && g.compareTo(p.subtract(BigInteger.ONE)) < 0){
                // g^(p-1)/2
                BigInteger left = fastExpo(g, (p.subtract(BigInteger.ONE)).divide(BigInteger.TWO), p); 

                // 1 mod p
                BigInteger right = BigInteger.ONE;
                
                //Check Is Generator g^(p-1)/2 mod p = 1 mod p
                if(left.compareTo(right) != 0){
                    break;
                }else{
                    g = g.negate().mod(p);
                    break;
                }
            }
        }
        return g;
    }

    public static BigInteger generateK(BigInteger p){
        BigInteger k = BigInteger.ZERO;
        
        while(true){
            //Generate K
            k = randomBigInt(BigInteger.ONE, p);

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
        BigInteger k = BigInteger.ZERO;

        while(true){
            //Generate K
            k = randomBigInt(BigInteger.ONE, p);

            //Random Number K Range =  1 < k < p-1
            if(k.compareTo(BigInteger.ONE) > 0 && k.compareTo(p.subtract(BigInteger.ONE)) < 0){
                break;
            }
        }
        return k;
    }

    public static BigInteger genPublicKey(BigInteger primeNum, BigInteger generator, BigInteger k){
        // y = g^k mod p
        BigInteger publicKey = fastExpo(generator, k, primeNum);

        // If Public Key < 0 Show Fail Message
        if(publicKey.compareTo(BigInteger.ONE) < 0){
            System.out.println("Generate Public Key Fail !!");
        }
        return publicKey;
    }

    private static void createPrivateFile(String path, BigInteger privateKeyA) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(path))) {
            //write r on the first line
            writer.write(privateKeyA.toString());
            System.out.println("PrivateKey file created successfully!");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void createHashFile(String path, BigInteger hash) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(path))) {
            //write r on the first line
            writer.write(hash.toString());
            System.out.println("Hash file created successfully!");
        } catch (IOException e) {
            e.printStackTrace();
        }
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

            System.out.println("PublicKey file created successfully!");
        } catch (IOException e) {
            e.printStackTrace();
        }
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

    public static byte[] encryption(byte[] plain_bytes, BigInteger primeNum, BigInteger generator, BigInteger publicKey){
        List<Integer> cipherList = new ArrayList<Integer>();
        byte[] prime_bytes = primeNum.toByteArray();

        for(byte plainByte: plain_bytes){
            //Generate Random Number K
            BigInteger k = generateK(primeNum);

            /* <----------------------------------------- a -----------------------------------------> */
            
            //Calculate a = g^k mod p
            BigInteger a = fastExpo(generator, k, primeNum);            
            
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
            BigInteger y_pow_k = fastExpo(publicKey, k, primeNum);
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
        return cipher_byte;
    }

    public static byte[] decryption(byte[] cipher_bytes, BigInteger primeNum, BigInteger privateKey){
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
            a = fastExpo(a, privateKey, primeNum);

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

        return plain_bytes;
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
            

            System.out.println("Signature file created successfully!");
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
    
    public static BigInteger[] signHash(BigInteger p,BigInteger g, BigInteger sk, byte[] plainBytes){
        BigInteger[] result = new BigInteger[3];
        BigInteger hash = hash(plainBytes).mod(p);
        System.out.println("Hash: " + hash);
        BigInteger K = generateK(p);
        BigInteger ink = K.modInverse(p.subtract(BigInteger.ONE));
        BigInteger r = fastExpo(g, K, p);
        BigInteger s = (ink.multiply(hash.subtract(sk.multiply(r)))).mod(p.subtract(BigInteger.ONE));
        result[0] = r;
        result[1] = s;
        result[2] = hash;
        return result;
    }

    public static boolean verify(BigInteger g, BigInteger pk, BigInteger plain, BigInteger r, BigInteger s, BigInteger p){
        // Convert BigInteger to byte array
        byte[] byteArray = plain.toByteArray();
        BigInteger X = hash(byteArray).mod(p);
        System.out.print("X : " + X + " ");
        BigInteger GpowX = fastExpo(g, X, p);
        System.out.print("GpowX = " + GpowX + " ");
        BigInteger yr = fastExpo(pk, r, p);
        BigInteger rs = fastExpo(r, s, p);
        BigInteger total = yr.multiply(rs).mod(p);
        System.out.print("Total = " + total + "  ");
        System.out.print("G = " + g + " ");
        System.out.print("Y = " + pk + "  ");
        System.out.print("R = " + r + "  ");
        System.out.print("S = " + s + "  ");
        if(GpowX.equals(total) == true){
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
