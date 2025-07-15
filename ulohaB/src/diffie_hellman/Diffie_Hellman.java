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
 * Tøída, která naète data ze souboru diffie_hellman_keys.csv obsahující Deffie-Hellmanovy klíèe a soukromé klíèe,
 * které mají být dešifrovány. Poté pro každý øádek souboru (každý øádek pøedstavuje jeden klíè) program použije metodu crackPrivateKey(),
 * která dešifruje soukromý klíè na základì veøejného klíèe.
 * Výsledky jsou ukládány do nového souboru alices_private_keys_A21B0625P.csv.
 * Pokud doba trvání dešifrování pøekroèí maximální dobu MAX_RUNTIME (15 minut), program se ukonèí.
 * @author Štìpán Lukeš
 * @version 1.00.0000 4-20-2023
 * 
 * */

public class Diffie_Hellman {

	// Definice maximální doby bìhu programu v sekundách (15 minut).
	private static final int MAX_RUNTIME = 900;

	// Konstanta pro hodnotu 2.
	private static final BigInteger TWO = new BigInteger("2");

	/**
	 * Hlavní metoda programu.
	 * Naète data z CSV souboru, dešifruje soukromé klíèe pomocí metody crackPrivateKey(),
	 * zaznamenává dobu trvání a výsledky ukládá do nového CSV souboru.
	 * Pokud doba trvání pøekroèí maximální dobu MAX_RUNTIME, program se ukonèí.
	 */
	public static void main(String[] args) {
	    // Naètení dat z CSV souboru.
	    List<String[]> csvData = readCsvFile("diffie_hellman_keys.csv");

	    // Inicializace seznamu pro ukládání výsledkù.
	    List<String[]> results = new ArrayList<>();

	    // Procházení každého øádku v CSV souboru.
	    for (int i = 1; i < csvData.size(); i++) {
	        String[] row = csvData.get(i);

	        // Získání parametrù pro Deffie-Hellmanùv klíèový výmìnný protokol.
	        int pLength = Integer.parseInt(row[0]);
	        int privateKeyLength = Integer.parseInt(row[1]);
	        BigInteger p = new BigInteger(row[2]);
	        BigInteger g = new BigInteger(row[3]);
	        BigInteger gxModP = new BigInteger(row[4]);

	        // Mìøení èasu bìhu metody pro dešifrování soukromého klíèe.
	        double startTime = System.currentTimeMillis();
	        BigInteger privateKey = crackPrivateKey(p, g, gxModP, privateKeyLength);
	        double elapsedTime = (System.currentTimeMillis() - startTime) / 1000.0;

	        // Uložení výsledku do seznamu.
	        results.add(new String[] { privateKey.toString(), Double.toString(elapsedTime) });

	        // Výpis výsledku a doby trvání.
	        System.out.println("Private key found: " + privateKey + ", elapsed time: " + elapsedTime + " seconds");

	        // Pokud doba trvání pøekroèí maximální dobu MAX_RUNTIME, program se ukonèí.
	        if (elapsedTime > MAX_RUNTIME) {
	            System.out.println("Maximum runtime exceeded. Exiting program.");
	            break;
	        }
	    }

	    // Uložení výsledkù do nového CSV souboru.
	    writeCsvFile("alices_private_keys_A21B0625P.csv", results);
	}


	/**
	 * Metoda pro prolomení soukromého klíèe pøi znalosti veøejného klíèe Diffie-Hellmanova klíèového výmìnného protokolu.
	 * @param p prvoèíslo použité pro generování klíèù
	 * @param g generátor grupy
	 * @param gxModP výsledek výpoètu g^x mod p (veøejný klíè)
	 * @param privateKeyLength délka soukromého klíèe v bitech
	 * @return vypoèítaný soukromý klíè nebo BigInteger.ZERO, pokud byla pøekroèena maximální délka soukromého klíèe
	 */
	private static BigInteger crackPrivateKey(BigInteger p, BigInteger g, BigInteger gxModP, int privateKeyLength) {
	    BigInteger privateKey = BigInteger.ZERO;
	    BigInteger candidate = TWO;
	    
	    // Pøiøazení hodnoty soukromého klíèe
	    while (!gxModP.equals(g.modPow(candidate, p))) {
	        // Kontrola délky soukromého klíèe
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
     * Ète CSV soubor a vrací jeho obsah jako List<String[]>.
     *
     * @param fileName název souboru k pøeètení
     * @return List<String[]> obsah CSV souboru
     */
    private static List<String[]> readCsvFile(String fileName) {
        // vytvoøení instance ArrayList pro uložení dat ze souboru
        List<String[]> data = new ArrayList<>();
        
        // otevøení souboru pro ètení a uložení do instance BufferedReader
        try (BufferedReader br = new BufferedReader(new FileReader(fileName))) {
            String line;
            
            // naèítání øádek ze souboru, dokud není dosaženo konce souboru
            while ((line = br.readLine()) != null) {
                // rozdìlení øádku na jednotlivé hodnoty oddìlené støedníkem
                String[] row = line.split(";");
                // uložení hodnot do ArrayListu
                data.add(row);
            }
        } catch (IOException e) {
            // výpis chyby na standardní výstup
            e.printStackTrace();
        }
        
        // vrácení dat z CSV souboru
        return data;
    }


    /**
     * Zapíše zadaná data do CSV souboru se zadaným názvem.
     * 
     * @param fileName název CSV souboru, do kterého budou data zapsána
     * @param data seznam øetìzcù, které budou zapsány do souboru
     */
    private static void writeCsvFile(String fileName, List<String[]> data) {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(fileName))) {
//        	// zápis záhlaví souboru
//        	String [] nazvy = new String [] {"soukromy klic", "cas k prolomeni ve vterinach"};
//        	bw.write(nazvy[0] + ";" + nazvy [1] + "\n");
        	
        	// zápis dat ze seznamu do souboru
            for (String[] row : data) {
                bw.write(row[0] + ";" + row[1] + "\n");
            }
        } catch (IOException e) {
            // výpis chyby na standardní výstup
            e.printStackTrace();
        }
    }

}
