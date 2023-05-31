package AsymmeticEncryption;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.Scanner;
import java.util.Set;

public class checkG {
    public static void main(String[] args) {
        checkGenerator(BigInteger.valueOf(383),BigInteger.valueOf(99));
    }
    public static void checkGenerator(BigInteger n, BigInteger q) {
        Set<Integer> set = new HashSet<>();
        int n2 = n.intValue();
        int q2 = q.intValue();
        for (int i = 1; i < n2-1; i++) {
            if (set.contains(((int) (Math.pow(q2, i)) % n2))){
                System.out.println("i : " + i);
                System.out.println("Duplicate : " + (Math.pow(q2, i) % n2));
            }
            else {
                set.add(((int) (Math.pow(q2, i)) % n2));
            }
        }
    }
}
