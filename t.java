package AsymmeticEncryption;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class t {
    public static void main(String[] args) {
        List<Integer> t = new ArrayList<Integer>();

        BigInteger num = new BigInteger("143");
        byte[] pB = num.toByteArray();
        System.out.println(pB.length);

        System.out.println("==================================");
        for(int i = 0; i < pB.length; i++){

            if(pB[i] != 0){
                t.add((int)pB[i]);
            }
        }
        
        byte[] out = new byte[t.size()];
        for (int i = 0; i < t.size(); i++) {
            System.out.println(t.get(i).byteValue());
            out[i] = t.get(i).byteValue();
        }

        BigInteger result = new BigInteger(out);
        System.out.println("result = " + result);

        BigInteger b = BigInteger.TWO;
        long o = (long)Math.pow(7, 6);
        o = o % 11;
        BigInteger a = BigInteger.valueOf(o);
        System.out.println("1a "+a);

        a = a.modInverse(BigInteger.valueOf(11));
        System.out.println("a "+a);
        BigInteger an = b.multiply(a).mod(BigInteger.valueOf(11));
        System.out.println("an = " + an);
    }
}
