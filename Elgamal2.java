import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
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
                //get public key sender

                //get file

                System.out.println("    Encryption Process ...");
                
                //gen k

                //create file encryption

                System.out.println("<<< Encryption Finish >>>");
            }
            
            if(c.equalsIgnoreCase("decryption")){
                //get encryption file
                
                //get self private key

                //create decryp file

                System.out.println("    Decryption Process ...");
                System.out.println("<<< Decryption Finish >>>");
                
            }

            if(c.equalsIgnoreCase("signature")){
                System.out.println("    Create Digital Signature ...");
                System.out.println("<<< Digital Signature Create Finish >>>");
            }

            if(c.equalsIgnoreCase("verify")){
                System.out.println("    Verifying ...");
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
/* 
    public static boolean isPrimeNumber(BigInteger num){
        boolean isPrime = true;

        // If Number Is Event Return Not Prime Number
        if((num.mod(BigInteger.TWO)).compareTo(BigInteger.ZERO) == 0){
            isPrime = false;
            return isPrime;
        }

        for (BigInteger i = BigInteger.TWO; i.compareTo(num.sqrt()) <= 0; i = i.add(BigInteger.ONE)) {
          if (num.mod(i).equals(BigInteger.ZERO)) {
            isPrime = false;
            break;
          }
        }
        return isPrime;
    }*/
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
}
