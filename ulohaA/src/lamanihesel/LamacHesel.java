package lamanihesel;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/** 
 * T��da, kter� slou�� k prolomen� hesel.
 * Po spu�t�n� na�te soubor se seznamem hesel a soubor se slovn�kem hesel.
 * Pot� aplikace pro ka�d� heslo postupn� zkou�� hesla ze slovn�ku a pak hesla metodou brute force, dokud nenajde spr�vn� heslo nebo nen� p�ekro�en �asov� limit.
 * Pokud heslo nen� nalezeno, je vytvo�en z�znam "not_cracked". V�sledky jsou pak zaps�ny do v�stupn�ho souboru v CSV form�tu.
 * @author Stepan Lukes
 * @version 1.00.0000 04-28-2023
 * */

public class LamacHesel {
	
	// hlavn� metoda
    public static void main(String[] args) {
    	// Nastaven� prom�nn�ch pro soubory a maxim�ln� d�lky hesel
        String nazevSouboru = "password_database.csv";
        String osobniCislo = "A21B0625P";
        String slovnikovySoubor = "10000hesel.txt";
        int maxDelkaHesla = 6;
        long maxDelkaVeVterinach = 180;
        String nazevVystupnihoSouboru = "cracked_results_A21B0625P.csv";

     // Na�ten� slovn�ku hesel
        List<String> slovnik = prectiSlovnikovySoubor(slovnikovySoubor);

        // Na�ten� hash� hesel pro dan�ho u�ivatele
        List<String> hasheHesel = prectiHeslovouDatabazy(nazevSouboru, osobniCislo);

        // Vytvo�en� pr�zdn�ho seznamu pro v�sledky prolomen� hesel
        List<LamacHeselVysledek> vysledky = new ArrayList<>();

        // Pro ka�d� hash hesla v datab�zi se prov�d� prolomen� hesla
        for (String hashHesla : hasheHesel) {
            String prolomeneHeslo = null; // inicializace prom�nn� pro v�sledn� prolomen� heslo
            long pocetPokusu = 0; // inicializace prom�nn� pro po�et pokus� p�i prolomen� hesla
            long zacatekMereni = System.nanoTime(); // zah�jen� m��en� �asu

            // Slovn�kov� �tok - porovn�v�n� hash� hesla s hesly ze slovn�ku
            for (String slovnikoveHeslo : slovnik) {
                pocetPokusu++; // zv��en� po�tu pokus� o prolomen� hesla
                if (hash(slovnikoveHeslo).equals(hashHesla)) {
                    prolomeneHeslo = slovnikoveHeslo; // nalezen� shody hash�, heslo bylo prolomeno
                    break;
                }
            }

            // pokud nevyjde slovnikovy utok, pouzije se brute force
            
            if (prolomeneHeslo == null) {
                for (int i = 1; i <= maxDelkaHesla; i++) {
                	// Vypo��t� po�et kombinac� pro danou d�lku hesla.
                	
                    long pocetKombinaci = (long) Math.pow(36, i);
                    
                    // Pokud se po�et kombinac� vejde do rozsahu long, spust� se bruteforce �tok.
                    if (pocetKombinaci < Long.MAX_VALUE - pocetPokusu) {
                    	// Generuje hesla pro danou d�lku i a testuje, zda-li se shoduj� s hashem hesla.
                        for (String heslo : generujHesla(i)) {
                            pocetPokusu++;
                            if (hash(heslo).equals(hashHesla)) {
                            	// Pokud se heslo shoduje s hashem hesla, nastav� se prolomeneHeslo a ukon�� se for cyklus.
                            	
                                prolomeneHeslo = heslo;
                                break;
                            }
                        }
                       
                    } 
                    
                    else {
                    	// Pokud je po�et kombinac� p��li� velk�, zastav� se bruteforce �tok a pokra�uje se s dal��m
                        break;
                    }
                 // Pokud bylo heslo prolomeno, ukon�� se for cyklus.
                    if (prolomeneHeslo != null) {
                        break;
                    }
                }
                
            }
            
            // M��� celkovou d�lku b�hu programu
            long konecMereni = System.nanoTime();
            double delkaVeVterinach = (konecMereni - zacatekMereni) / 1e9;
            
         // Pokud heslo nebylo prolomeno, p�id� se v�sledek "not_cracked" do v�sledk�.
            if (prolomeneHeslo == null) {
                vysledky.add(new LamacHeselVysledek(hashHesla, "not_cracked", pocetPokusu, delkaVeVterinach));
                System.out.println("Heslo neprolomeno:" + " Hash uzivatele: " + hashHesla + ", not_cracked" + ", pocet pokusu: " + pocetPokusu + ", cas: " + delkaVeVterinach + "s" );
            } else {
            	// Pokud heslo bylo prolomeno, p�id� se prolomen� heslo do v�sledk�.
            	String trimmedPassword = prolomeneHeslo.trim();
                vysledky.add(new LamacHeselVysledek(hashHesla, trimmedPassword, pocetPokusu, delkaVeVterinach));
                System.out.println("Heslo prolomeno:" + " Hash uzivatele: " + hashHesla + ", heslo: " + trimmedPassword + ", pocet pokusu: " + pocetPokusu + ", cas: " + delkaVeVterinach + "s" );
            }

            
            // Pokud je p�ekro�en �asov� limit, p�id� se v�sledek "not_cracked" do v�sledk� a ukon�� se cyklus.
            if (delkaVeVterinach >= maxDelkaVeVterinach) {
            	vysledky.add(new LamacHeselVysledek(hashHesla, "not_cracked", pocetPokusu, delkaVeVterinach));
                break;
            }
            
        }
        
        // Zap�e v�sledky do v�stupn�ho souboru.
        zapisVysledekDoSouboru(nazevVystupnihoSouboru, vysledky);
    }

    /**
     * Metoda p�e�te slovn�kov� soubor a ulo�� jednotliv� ��dky jako polo�ky do seznamu.
     * 
     * @param nazevSouboru n�zev souboru, kter� se m� p�e��st
     * @return seznam �et�zc� obsahuj�c�ch jednotliv� ��dky ze souboru
     */
    private static List<String> prectiSlovnikovySoubor(String nazevSouboru) {
        // Vytvo�en� pr�zdn�ho seznamu pro ulo�en� ��dk� ze souboru
        List<String> slovnik = new ArrayList<>();
        
        // Pokus o otev�en� souboru pro �ten� pomoc� try-with-resources bloku pro automatick� uzav�en� readeru
        try (BufferedReader reader = new BufferedReader(new FileReader(nazevSouboru))) {
            // Prom�nn� pro ukl�d�n� na�ten� ��dky
            String radka;
            
            // �ten� souboru ��dek po ��dku, dokud se nedos�hne konce souboru
            while ((radka = reader.readLine()) != null) {
                // Odstran�n� p��padn�ch mezer z po��tku a konce na�ten�ho ��dku a p�id�n� do seznamu slovn�ku
                slovnik.add(radka.trim() + "\n");
            }
        } catch (IOException e) {
            // Pokud do�lo k chyb� p�i �ten� souboru, vytiskne se v�jimka
            e.printStackTrace();
        }
        
        // Vr�cen� seznamu slovn�ku
        return slovnik;
    }

              
    /**
     * Na�te hesla u�ivatele s dan�m osobn�m ��slem ze souboru heslov� datab�ze.
     *
     * @param nazevSouboru n�zev souboru heslov� datab�ze
     * @param osobniCislo osobn� ��slo u�ivatele
     * @return seznam hash� hesel u�ivatele
     */
    private static List<String> prectiHeslovouDatabazy(String nazevSouboru, String osobniCislo) {
        // inicializace seznamu hash� hesel
        List<String> hasheHesel = new ArrayList<>();
        
        try (BufferedReader reader = new BufferedReader(new FileReader(nazevSouboru))) {
            String radka;
            // �ten� souboru po ��dc�ch
            while ((radka = reader.readLine()) != null) {
                // rozd�len� ��dky na pole podle odd�lova�e ","
                String[] pole = radka.trim().split(",");
                // na�ten� aktu�ln�ho u�ivatele a hashe jeho hesla
                String aktulaniUzivatel = pole[0];
                String hashHesla = pole[1];
                // porovn�n� aktu�ln�ho u�ivatele s hledan�m osobn�m ��slem
                if (aktulaniUzivatel.equals(osobniCislo)) {
                    // p�id�n� hashe hesla do seznamu
                    hasheHesel.add(hashHesla);
                }
            }
        } catch (IOException e) {
            // zachycen� v�jimky a v�pis chyby na standardn� v�stup
            e.printStackTrace();
        }
        // vr�cen� seznamu hash� hesel
        return hasheHesel;
    }

           
 // Metoda pro vytvo�en� SHA-256 hash ze vstupn�ho �et�zce
    private static String hash(String input) {
        try {
            // Vytvo�en� instance MessageDigest objektu s algoritmem SHA-256
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            
            // Vypo��t�n� hash byt� pro vstupn� �et�zec pomoc� metody digest() z MessageDigest
            byte[] hashBytes = md.digest(input.getBytes(StandardCharsets.UTF_8));
            
            // P�evod bytov�ho pole na BigInteger s hodnotou 1 pro kladnost a hash byty jako druh� parametr
            BigInteger hashNum = new BigInteger(1, hashBytes);
            
            // P�evod BigInteger na �et�zec v �estn�ctkov� soustav� a vr�cen� v�sledku
            return hashNum.toString(16);
        } catch (NoSuchAlgorithmException e) {
            // Pokud algoritmus neexistuje, vyp�e se stack trace a vr�t� se hodnota null
            e.printStackTrace();
            return null;
        }
    }

     
    
     
    /**
     * Generuje seznam hesel dan� d�lky.
     *
     * @param delka d�lka generovan�ch hesel
     * @return seznam hesel dan� d�lky
     */
    private static List<String> generujHesla(int delka) {
        char[] znaky = "0123456789abcdefghijklmnopqrstuvwxyz".toCharArray();
        List<String> hesla = new ArrayList<>();

        // rekurzivn� generuje v�echna hesla
        generujHeslaPomocnik(delka, znaky, "", hesla);

        return hesla;
    }

    /**
     * Rekurzivn� funkce, kter� generuje v�echna hesla dan� d�lky.
     *
     * @param delka d�lka generovan�ch hesel
     * @param znaky seznam povolen�ch znak� pro hesla
     * @param heslo aktu�ln� heslo
     * @param hesla seznam v�ech vygenerovan�ch hesel
     */
    private static void generujHeslaPomocnik(int delka, char[] znaky, String heslo, List<String> hesla) {
        if (delka == 0) {
            // p�id� aktu�ln� heslo do seznamu hesel
            hesla.add(heslo + "\n");
        } else {
            // rekurzivn� vol� sebe sama pro ka�d� mo�n� znak a� do dosa�en� d�lky hesla
            for (char c : znaky) {
                generujHeslaPomocnik(delka - 1, znaky, heslo + c, hesla);
            }
        }
    }

   
    
    /**
     * Zapisuje v�sledky l�m�n� hesel do souboru.
     * @param nazevSouboru n�zev souboru, do kter�ho budou v�sledky zaps�ny
     * @param vysledky seznam v�sledk�, kter� maj� b�t zaps�ny
     */
    private static void zapisVysledekDoSouboru(String nazevSouboru, List<LamacHeselVysledek> vysledky) {
        try (java.io.FileWriter writer = new java.io.FileWriter(nazevSouboru)) {
            // proch�zen� v�sledk� a z�pis ka�d�ho z nich na jednu ��dku souboru
            for (LamacHeselVysledek vysledek : vysledky) {
                // sestaven� ��dky ve form�tu "username_hash,cracked_password,num_tries,elapsed_time_seconds\n"
                String radka = vysledek.getUsernameHash() + "," + vysledek.getCrackedPassword() + ","
                        + vysledek.getNumTries() + "," + vysledek.getElapsedTimeSeconds() + "\n";
                // z�pis ��dky do souboru
                writer.write(radka);
            }
        } catch (IOException e) {
            // pokud dojde k chyb� p�i z�pisu, vyp�e se chybov� hl�en�
            e.printStackTrace();
        }
    }

}

class LamacHeselVysledek {
    // deklarace soukrom�ch instan�n�ch prom�nn�ch
    private String hashUzivatele;
    private String prolomeneHeslo;
    private long pocetPokusu;
    private double casVeVterinach;

    // konstruktor t��dy LamacHeselVysledek, p�ij�maj�c� n�kolik parametr�
    public LamacHeselVysledek(String hashUzivatele, String prolomeneHeslo, long pocetPokusu, double casVeVterinach) {
        // inicializace soukrom�ch instan�n�ch prom�nn�ch hodnotami z parametr�
        this.hashUzivatele = hashUzivatele;
        this.prolomeneHeslo = prolomeneHeslo;
        this.pocetPokusu = pocetPokusu;
        this.casVeVterinach = casVeVterinach;
    }

    // metoda pro z�sk�n� hashe u�ivatelsk�ho jm�na
    public String getUsernameHash() {
        return hashUzivatele;
    }

    // metoda pro z�sk�n� prolomen�ho hesla
    public String getCrackedPassword() {
        return prolomeneHeslo;
    }

    // metoda pro z�sk�n� po�tu pokus�
    public long getNumTries() {
        return pocetPokusu;
    }

    // metoda pro z�sk�n� �asu, kter� byl pot�eba pro prolomen� hesla
    public double getElapsedTimeSeconds() {
        return casVeVterinach;
    }
}