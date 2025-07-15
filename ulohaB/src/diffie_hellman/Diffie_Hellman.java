package diffie_hellman;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/** 
 * T��da, kter� na�te data ze souboru diffie_hellman_keys.csv obsahuj�c� Deffie-Hellmanovy kl��e a soukrom� kl��e,
 * kter� maj� b�t de�ifrov�ny. Pot� pro ka�d� ��dek souboru (ka�d� ��dek p�edstavuje jeden kl��) program pou�ije metodu crackPrivateKey(),
 * kter� de�ifruje soukrom� kl�� na z�klad� ve�ejn�ho kl��e.
 * V�sledky jsou ukl�d�ny do nov�ho souboru alices_private_keys_A21B0625P.csv.
 * Pokud doba trv�n� de�ifrov�n� p�ekro�� maxim�ln� dobu MAX_RUNTIME (15 minut), program se ukon��.
 * @author �t�p�n Luke�
 * @version 1.00.0000 4-20-2023
 * 
 * */

public class Diffie_Hellman {

	// Definice maxim�ln� doby b�hu programu v sekund�ch (15 minut).
	private static final int MAX_RUNTIME = 900;

	// Konstanta pro hodnotu 2.
	private static final BigInteger TWO = new BigInteger("2");

	/**
	 * Hlavn� metoda programu.
	 * Na�te data z CSV souboru, de�ifruje soukrom� kl��e pomoc� metody crackPrivateKey(),
	 * zaznamen�v� dobu trv�n� a v�sledky ukl�d� do nov�ho CSV souboru.
	 * Pokud doba trv�n� p�ekro�� maxim�ln� dobu MAX_RUNTIME, program se ukon��.
	 */
	public static void main(String[] args) {
	    // Na�ten� dat z CSV souboru.
	    List<String[]> csvData = readCsvFile("diffie_hellman_keys.csv");

	    // Inicializace seznamu pro ukl�d�n� v�sledk�.
	    List<String[]> results = new ArrayList<>();

	    // Proch�zen� ka�d�ho ��dku v CSV souboru.
	    for (int i = 1; i < csvData.size(); i++) {
	        String[] row = csvData.get(i);

	        // Z�sk�n� parametr� pro Deffie-Hellman�v kl��ov� v�m�nn� protokol.
	        int pLength = Integer.parseInt(row[0]);
	        int privateKeyLength = Integer.parseInt(row[1]);
	        BigInteger p = new BigInteger(row[2]);
	        BigInteger g = new BigInteger(row[3]);
	        BigInteger gxModP = new BigInteger(row[4]);

	        // M��en� �asu b�hu metody pro de�ifrov�n� soukrom�ho kl��e.
	        double startTime = System.currentTimeMillis();
	        BigInteger privateKey = crackPrivateKey(p, g, gxModP, privateKeyLength);
	        double elapsedTime = (System.currentTimeMillis() - startTime) / 1000.0;

	        // Ulo�en� v�sledku do seznamu.
	        results.add(new String[] { privateKey.toString(), Double.toString(elapsedTime) });

	        // V�pis v�sledku a doby trv�n�.
	        System.out.println("Private key found: " + privateKey + ", elapsed time: " + elapsedTime + " seconds");

	        // Pokud doba trv�n� p�ekro�� maxim�ln� dobu MAX_RUNTIME, program se ukon��.
	        if (elapsedTime > MAX_RUNTIME) {
	            System.out.println("Maximum runtime exceeded. Exiting program.");
	            break;
	        }
	    }

	    // Ulo�en� v�sledk� do nov�ho CSV souboru.
	    writeCsvFile("alices_private_keys_A21B0625P.csv", results);
	}


	/**
	 * Metoda pro prolomen� soukrom�ho kl��e p�i znalosti ve�ejn�ho kl��e Diffie-Hellmanova kl��ov�ho v�m�nn�ho protokolu.
	 * @param p prvo��slo pou�it� pro generov�n� kl���
	 * @param g gener�tor grupy
	 * @param gxModP v�sledek v�po�tu g^x mod p (ve�ejn� kl��)
	 * @param privateKeyLength d�lka soukrom�ho kl��e v bitech
	 * @return vypo��tan� soukrom� kl�� nebo BigInteger.ZERO, pokud byla p�ekro�ena maxim�ln� d�lka soukrom�ho kl��e
	 */
	private static BigInteger crackPrivateKey(BigInteger p, BigInteger g, BigInteger gxModP, int privateKeyLength) {
	    BigInteger privateKey = BigInteger.ZERO;
	    BigInteger candidate = TWO;
	    
	    // P�i�azen� hodnoty soukrom�ho kl��e
	    while (!gxModP.equals(g.modPow(candidate, p))) {
	        // Kontrola d�lky soukrom�ho kl��e
	        if (candidate.bitLength() > privateKeyLength) {
	            System.out.println("Maximum length of the privateKey exceeded.");
	            return BigInteger.ZERO;
	        }
	        candidate = candidate.add(BigInteger.ONE);
	    }
	    privateKey = candidate;
	    return privateKey;
	}


    /**
     * �te CSV soubor a vrac� jeho obsah jako List<String[]>.
     *
     * @param fileName n�zev souboru k p�e�ten�
     * @return List<String[]> obsah CSV souboru
     */
    private static List<String[]> readCsvFile(String fileName) {
        // vytvo�en� instance ArrayList pro ulo�en� dat ze souboru
        List<String[]> data = new ArrayList<>();
        
        // otev�en� souboru pro �ten� a ulo�en� do instance BufferedReader
        try (BufferedReader br = new BufferedReader(new FileReader(fileName))) {
            String line;
            
            // na��t�n� ��dek ze souboru, dokud nen� dosa�eno konce souboru
            while ((line = br.readLine()) != null) {
                // rozd�len� ��dku na jednotliv� hodnoty odd�len� st�edn�kem
                String[] row = line.split(";");
                // ulo�en� hodnot do ArrayListu
                data.add(row);
            }
        } catch (IOException e) {
            // v�pis chyby na standardn� v�stup
            e.printStackTrace();
        }
        
        // vr�cen� dat z CSV souboru
        return data;
    }


    /**
     * Zap�e zadan� data do CSV souboru se zadan�m n�zvem.
     * 
     * @param fileName n�zev CSV souboru, do kter�ho budou data zaps�na
     * @param data seznam �et�zc�, kter� budou zaps�ny do souboru
     */
    private static void writeCsvFile(String fileName, List<String[]> data) {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(fileName))) {
//        	// z�pis z�hlav� souboru
//        	String [] nazvy = new String [] {"soukromy klic", "cas k prolomeni ve vterinach"};
//        	bw.write(nazvy[0] + ";" + nazvy [1] + "\n");
        	
        	// z�pis dat ze seznamu do souboru
            for (String[] row : data) {
                bw.write(row[0] + ";" + row[1] + "\n");
            }
        } catch (IOException e) {
            // v�pis chyby na standardn� v�stup
            e.printStackTrace();
        }
    }

}
