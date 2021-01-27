package me.mingshan.encryption.symmetric;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.io.IOException;
import java.security.SecureRandom;

/**
 * DES 加密算法是一种分组密码，以 64 位为分组对数据加密，它的密钥长度是 56 位，加密解密用同一算法。DES 加密算法是对密钥进行保密，
 * 而公开算法，包括加密和解密算法。这样，只有掌握了和发送方相同密钥的人才能解读由 DES 加密算法加密的密文数据。
 * 因此，破译 DES 加密算法实际上就是搜索密钥的编码。对于 56 位长度的密钥来说，如果用穷举法来进行搜索的话，其运算次数为 2 的 56 次方。
 *
 * @author Walker Han
 * @date 2021/1/27 10:22
 */
public class DESTest {
  private final static String DES = "DES";

  public static void main(String[] args) throws Exception {
    String data = "123 456";
    String key = "wang!@#$";
    System.err.println(encrypt(data, key));
    System.err.println(decrypt(encrypt(data, key), key));
  }

  /**
   * Description 根据键值进行加密
   *
   * @param data
   * @param key  加密键byte数组
   * @return
   * @throws Exception
   */
  public static String encrypt(String data, String key) throws Exception {
    byte[] bt = encrypt(data.getBytes(), key.getBytes());
    return new BASE64Encoder().encode(bt);
  }

  /**
   * Description 根据键值进行解密
   *
   * @param data
   * @param key  加密键byte数组
   * @return
   * @throws IOException
   * @throws Exception
   */
  public static String decrypt(String data, String key) throws IOException,
      Exception {
    if (data == null)
      return null;
    BASE64Decoder decoder = new BASE64Decoder();
    byte[] buf = decoder.decodeBuffer(data);
    byte[] bt = decrypt(buf, key.getBytes());
    return new String(bt);
  }

  /**
   * Description 根据键值进行加密
   *
   * @param data
   * @param key  加密键byte数组
   * @return
   * @throws Exception
   */
  private static byte[] encrypt(byte[] data, byte[] key) throws Exception {
    // 生成一个可信任的随机数源
    SecureRandom sr = new SecureRandom();

    // 从原始密钥数据创建DESKeySpec对象
    DESKeySpec dks = new DESKeySpec(key);

    // 创建一个密钥工厂，然后用它把DESKeySpec转换成SecretKey对象
    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DES);
    SecretKey secureKey = keyFactory.generateSecret(dks);

    // Cipher对象实际完成加密操作
    Cipher cipher = Cipher.getInstance(DES);

    // 用密钥初始化Cipher对象
    cipher.init(Cipher.ENCRYPT_MODE, secureKey, sr);

    return cipher.doFinal(data);
  }


  /**
   * Description 根据键值进行解密
   *
   * @param data
   * @param key  加密键byte数组
   * @return
   * @throws Exception
   */
  private static byte[] decrypt(byte[] data, byte[] key) throws Exception {
    // 生成一个可信任的随机数源
    SecureRandom sr = new SecureRandom();

    // 从原始密钥数据创建DESKeySpec对象
    DESKeySpec dks = new DESKeySpec(key);

    // 创建一个密钥工厂，然后用它把DESKeySpec转换成SecretKey对象
    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DES);
    SecretKey secureKey = keyFactory.generateSecret(dks);

    // Cipher对象实际完成解密操作
    Cipher cipher = Cipher.getInstance(DES);

    // 用密钥初始化Cipher对象
    cipher.init(Cipher.DECRYPT_MODE, secureKey, sr);

    return cipher.doFinal(data);
  }

}
