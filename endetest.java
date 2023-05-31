package AsymmeticEncryption;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;

public class endetest {
    public static void main(String[] args) {
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
        BigInteger prime = generateP(start, end);
        System.out.println("Prime " + prime);

        BigInteger generator = generateG(prime);
        System.out.println("Generator " + generator);

        BigInteger privatekey = genPrivateKey(prime);
        System.out.println("Privatekey " + privatekey);

        BigInteger publickey = genPublicKey(prime, generator, privatekey);
        System.out.println("Public key " + publickey);

        String s = "fuk u crypto";
        byte[] s_byte = s.getBytes();
        
        System.out.println("\nstring bytes >>>>>>>>");
        for (byte b : s_byte) {
            System.out.print(b + " ");
        }
        System.out.println("\n<<<<<<<< string bytes");



        BigInteger k = generateK(prime);
        System.out.println("k = "+ k);

        //a
        BigInteger a = generator.modPow(k, prime);
        System.out.println("a = " + a);
        System.out.println();

        //b
        BigInteger y_pow_k = publickey.modPow(k, prime);

        System.out.println("y_pow_k " + y_pow_k);
        System.out.println("s_byte[0] " + s_byte[0]);

        BigInteger b = (y_pow_k.multiply(BigInteger.valueOf(s_byte[0]))).mod(prime);
        System.out.println("b = " + b);
        System.out.println();

        a = a.modPow(privatekey, prime);
        System.out.println("a^u = " + a);
        a = a.modInverse(prime);
        System.out.println("aInvert = " + a);

        BigInteger x = (b.multiply(a)).mod(prime);

        System.out.println(x);
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
            if(p.compareTo(start) >= 0 && isPrimeNumber(p)){
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
        BigInteger publicKey = g.modPow(k, p);

        if(publicKey.compareTo(BigInteger.ONE) < 0){
            System.out.println("Generate Public Key Fail !!");
        }
        return publicKey;
    }
}
