/*
 * Copyright (c) 2020 Angel Castillo.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.ecdsa;

/* IMPORTS *******************************************************************/

import java.math.BigInteger;

/* STRUCTURES ****************************************************************/

/**
 * Elliptic curve point.
 */
class ECPoint
{
    public BigInteger x = BigInteger.ZERO;
    public BigInteger y = BigInteger.ZERO;

    /**
     * Initializes a new instance of the ECPoint class.
     */
    public ECPoint()
    {
    }

    /**
     * Initializes a new instance of the ECPoint class.
     *
     * @param x The X coordinate.
     * @param y The Y coordinate.
     */
    public ECPoint(BigInteger x, BigInteger y)
    {
        this.x = x;
        this.y = y;
    }

    @Override
    public String toString()
    {
        return String.format("[x: %s, y: %s]", x.toString(16), y.toString(16));
    }
}

/* IMPLEMENTATION ************************************************************/

/**
 * Application main class.
 */
public class Main
{
    // Public specs for the secp256k1 curve.

    // These two defines the elliptic curve. y^2 = x^3 + A * x + B
    static BigInteger A = BigInteger.ZERO;
    static BigInteger B = BigInteger.valueOf(7);

    // The proven prime
    static BigInteger P = new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16);

    // Number of points in the field.
    static BigInteger N = new BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);
    
    // This is our generator point. Trillions of dif ones possible
    static ECPoint    G = new ECPoint(
            new BigInteger("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16),
            new BigInteger("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16));

    // Private key.
    static BigInteger privKey = new BigInteger("A0DC65FFCA799873CBEA0AC274015B9526505DAAAED385155425F7337704883E", 16);

    // Replace with a truly random number
    static BigInteger randNum = new BigInteger("28695618543805844332113829720373285210420739438570883203839696518176414791234", 10);

    // The hash of your message/transaction
    static BigInteger hashOfThingToSign = new BigInteger("86032112319101611046176971828093669637772856272773459297323797145286374828050", 10);

    /**
     * Application entry point.
     *
     * @param args Arguments.
     */
    public static void main(String[] args)
    {
        System.out.println("******* Public Key Generation *********");
        ECPoint publicKey = pointMultiply(G, privKey);

        System.out.println(String.format("The private key: %s", privKey));
        System.out.println(String.format("The uncompressed public key: %s", publicKey));

        // If the Y value for the Public Key is odd.
        if (publicKey.y.mod(BigInteger.TWO).equals(BigInteger.ONE))
        {
            System.out.println(String.format("The compressed public key: 03%s", publicKey.x.toString(16)));
        }
        else
        {
            System.out.println(String.format("The compressed public key: 02%s", publicKey.x.toString(16)));
        }

        System.out.println("******* Signature Generation *********");
        ECPoint randomPoint = pointMultiply(G, randNum);
        BigInteger r = randomPoint.x.mod(N);
        System.out.println(String.format("r: %s", r.toString(16)));
        BigInteger s = (hashOfThingToSign.add(r.multiply(privKey)).multiply(randNum.modInverse(N))).mod(N);
        System.out.println(String.format("s: %s", s.toString(16)));

        System.out.println("******* Signature Verification *********");
        BigInteger w = s.modInverse(N);
        ECPoint u1 = pointMultiply(G, hashOfThingToSign.multiply(w).mod(N));
        ECPoint u2 = pointMultiply(publicKey, r.multiply(w).mod(N));
        ECPoint result = pointAddition(u1, u2);

        System.out.println(String.format("Verification: %s", result.x.equals(r) ? "Verified" : "Invalid Signature."));
    }

    /**
     * Adds two points over an elliptic curve.
     *
     * @param p1 The first point to be added.
     * @param p2 The second point to be added.
     *
     * @return A new point in the curve. Adding points in an elliptic curve always return a new point that
     * also belongs to the curve.
     */
    public static ECPoint pointAddition(ECPoint p1, ECPoint p2)
    {
        BigInteger a = (p2.y.subtract(p1.y));
        BigInteger b = (p2.x.subtract(p1.x));
        b = b.modInverse(P);
        a = a.multiply(b).mod(P);
        b = a.multiply(a);
        b = ((b.subtract(p1.x)).subtract(p2.x)).mod(P);

        ECPoint result = new ECPoint();

        result.x = b;
        result.y = (a.multiply(p1.x.subtract(b))).subtract(p1.y).mod(P);

        return result;
    }


    /**
     * Doubles a point in the curve.
     *
     * @param point The point to be doubled.
     *
     * @return The new point.
     */
    public static ECPoint pointDoubling(ECPoint point)
    {
        ECPoint val = new ECPoint();

        BigInteger i = point.x.multiply(point.x).multiply(BigInteger.valueOf(3)).add(A);
        BigInteger j = (point.y.multiply(BigInteger.valueOf(2))).modInverse(P);
        i = (i.multiply(j)).mod(P);
        j = i.multiply(i);
        j = (j.subtract(point.x.multiply(BigInteger.valueOf(2)))).mod(P);

        val.x = j;
        val.y = (i.multiply(point.x.subtract(j))).subtract(point.y).mod(P);

        return val;
    }

    /**
     * Elliptic curve scalar multiplication is the operation of successively adding a point along an elliptic curve to
     * itself repeatedly. It is used in elliptic curve cryptography (ECC) as a means of producing a one-way function.
     *
     * Iterative algorithm, index decreasing:
     *
     *   Q ← 0
     *   for i from m down to 0 do
     *      Q ← point_double(Q)
     *      if di = 1 then
     *          Q ← point_add(Q, P)
     *   return Q
     *
     * @param point  The point to be multiplied.
     * @param scalar The scalar number to be multiplied with.
     *
     * @return The new point along the curve.
     */
    public static ECPoint pointMultiply(ECPoint point, BigInteger scalar)
    {
        ECPoint result = new ECPoint();
        ECPoint doubledP = point;

        boolean set = false;

        String binMult = scalar.toString(2);
        int binMultLen = binMult.length();

        for (int c = binMultLen - 1; c >= 0; --c)
        {
            if (binMult.charAt(c) == '1')
            {
                if (set)
                {
                    result = pointAddition(result, doubledP);
                }
                else
                {
                    result = doubledP;
                    set = true;
                }
            }
            doubledP = pointDoubling(doubledP);
        }

        return result;
    }
}
