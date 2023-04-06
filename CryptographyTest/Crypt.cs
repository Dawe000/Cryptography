using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Chess0
{
    public class Crypt
    {
        uint[] P;
        uint[,] S;

        public Crypt(string pass)
        {
            InitBlowFish(MD5HashGen(pass));
        }


        void InitBlowFish(string Hash) //initialise variables for blowfish algorithm
        {
            S = SBox.Get();
            P = new uint[]{ 0x243f6a88, 0x85a308d3, 0x13198a21,
                0x03707344, 0xa4093822, 0x299f31d0, 0x082efa98,
                0xec4e6c89, 0x452821e6, 0x38d01377, 0xbe5466cf,
                0x34e90c6c, 0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5,
                0xb5470917, 0x9216d5d9, 0x8979fb1b};

            uint k;
            int p = 0;
            for (int i = 0; i < 18; i++)
            {
                k = 0x00;
                for (int j = 0; j < 4; j++)
                {
                    k = (k << 8) | (uint)Hash[p];
                    p = (p + 1) % Hash.Length;
                }
                P[i] ^= k;
            }

        }
        public string FullEncrypt(string plainText)
        {
            plainText = plainText.PadRight(plainText.Length + (8 - plainText.Length % 8), '^');
            string plainBin = ASCToBin(plainText);
            string cypherText = "";
            string tempHold;
            for (int i = 0; i < plainBin.Length; i += 64)
            {
                tempHold = plainBin.Substring(i, 64);
                cypherText += BEncrypt(Convert.ToUInt32(tempHold.Substring(0, 32), 2), Convert.ToUInt32(tempHold.Substring(32, 32), 2));
            }

            return cypherText;


        }//uses all other subroutines required to encrypt

        public string FullDecrypt(string CypherText)
        {
            string plainHex = "";
            string tempHold = "";
            for (int j = 0; j < CypherText.Length; j += 16)
            {
                tempHold = CypherText.Substring(j, 16);
                plainHex += BDecrypt(Convert.ToUInt32(tempHold.Substring(0, 8), 16), Convert.ToUInt32(tempHold.Substring(8, 8), 16));
            }
            string plainBin = String.Join(String.Empty, plainHex.Select(c => Convert.ToString(Convert.ToUInt32(c.ToString(), 16), 2).PadLeft(4, '0')));
            string plainText = BinToAsc(plainBin);
            return plainText;
        }
        uint RotateLeft(uint value, int count) //needed for algorithms
        {
            return (value << count) | (value >> (32 - count));
        }

        string ASCToBin(string pass) //convert ascii to bin subroutine
        {
            string passBin = ""; //init variable

            foreach (byte b in pass) //converting string to binary
            {
                string binByte = Convert.ToString(b, 2);
                while (binByte.Length < 8) binByte = "0" + binByte; //makes sure length of byte is 8 bits
                passBin += binByte;
            }

            return passBin;
        }

        string BinToAsc(string pass)
        {
            string passBin = "";

            while (pass.Length > 0)
            {
                var first8 = pass.Substring(0, 8);
                pass = pass.Substring(8);
                var number = Convert.ToInt32(first8, 2);
                passBin += (char)number;
            }

            return passBin;
        } //convert binary to ascii subroutine
        uint f(uint input)
        {
            uint temp = S[0, input >> 24] + S[1, (input >> 16) & 0xff];
            uint final = Convert.ToUInt32((temp ^ S[2, input >> 8 & 0xff]) + S[3, input & 0xFF]);
            return final;
        } //function needed in blowfish algorithm

        string BEncrypt(UInt32 L, UInt32 R)
        {
            uint temp;
            for (int i = 0; i < 16; i++)
            {
                L = L ^ P[i];
                R = f(L) ^ R;
                temp = L; L = R; R = temp;
            }

            temp = L; L = R; R = temp;
            R = R ^ P[16];
            L = L ^ P[17];
            return (Convert.ToString(L, 16).PadLeft(8, '0') + Convert.ToString(R, 16).PadLeft(8, '0'));

        } //encrypts a block for blowfish algorithm

        string BDecrypt(UInt32 L, UInt32 R)
        {
            uint temp;
            for (int i = 17; i > 1; i--)
            {
                L = L ^ P[i];
                R = f(L) ^ R;
                temp = L; L = R; R = temp;
            }
            temp = L; L = R; R = temp;
            R = R ^ P[1];
            L = L ^ P[0];
            return (Convert.ToString(L, 16).PadLeft(8, '0') + Convert.ToString(R, 16).PadLeft(8, '0'));
        } //decrypts a block for blowfish algorithm

        public string MD5HashGen(string pass) //using MD5 hashing algorithm: https://en.wikipedia.org/wiki/MD5. We do not care about the MD5 vulnerabilities, all we need it for is to convert a variable length string password into a fixed length hash for use the main encryption algorithm.
        {
            //initialising variables

            uint[] table = new uint[64]; // constants used in algorithm (K)
            int[] shifts = { 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21 }; //shift amounts (s)

            long tableItem; //working value used

            for (int i = 0; i < 64; i++)
            {
                tableItem = Convert.ToInt64(Math.Floor((Math.Pow(2, 32)) * Math.Abs(Math.Sin(i + 1)))); //integer parts of sines (radians) used as constants
                table[i] = Convert.ToUInt32("0x" + Convert.ToString(tableItem, 16), 16); //converting number to hex
            }

            while (pass.Length % 512 != 0) pass = pass + "0"; //right pad with 0s

            //starting constants:

            uint a0 = 0x67452301;   // A
            uint b0 = 0xefcdab89;   // B
            uint c0 = 0x98badcfe;   // C
            uint d0 = 0x10325476;   // D

            uint A = a0;
            uint B = b0;
            uint C = c0;
            uint D = d0;

            string passBin = ASCToBin(pass); //run convert string to binary subroutine

            uint[] passChunks = new uint[16]; //initialisation for final iteration of conversion
            string singleChunk; //variables needed to convert long string of binary to 32 16 bit chunks
            uint hexChunk;

            for (int i = 0; i < 16; i++)  //convert binary to 16 bit chunks
            {
                singleChunk = "";
                for (int y = 0; y < 32; y++)
                {
                    singleChunk += passBin[i * 16 + y];

                }
                hexChunk = Convert.ToUInt32(singleChunk, 2);
                passChunks[i] = hexChunk;
            }

            //everything is now prepared for the hash generation algorithm:

            for (int i = 0; i < 64; i++)
            {
                uint temp1; //F
                int temp2; //g

                if (i <= 15)
                {
                    temp1 = (B & C) | ((~B) & D);
                    temp2 = i;
                }
                else if (i <= 31)
                {
                    temp1 = (D & B) | ((~D) & C);
                    temp2 = (5 * i + 1) % 16;
                }
                else if (i <= 47)
                {
                    temp1 = B ^ C ^ D;
                    temp2 = (3 * i + 5) % 16;
                }
                else
                {
                    temp1 = C ^ (B | (~D));
                    temp2 = (7 * i) % 16;
                }

                temp1 = temp1 + A + table[i] + passChunks[temp2];
                A = D;
                D = C;
                C = B;
                B = B + RotateLeft(temp1, shifts[i]);

            }

            a0 += A;
            b0 += B;
            c0 += C;
            d0 += D;

            //convert answers to hex then to strings and left padding each with 0s in case a 0 lost from the beginning of an answer

            string strA = a0.ToString("x").PadLeft(8, '0');
            string strB = b0.ToString("x").PadLeft(8, '0');
            string strC = c0.ToString("x").PadLeft(8, '0');
            string strD = d0.ToString("x").PadLeft(8, '0');

            string result = strA + strB + strC + strD; //put answers together in a final hash key. note that the hash key changes massively even with minute changes to the input password
            return result;

        }
    }
}

