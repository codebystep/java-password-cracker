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
 * Tøída, která slouží k prolomení hesel.
 * Po spuštìní naète soubor se seznamem hesel a soubor se slovníkem hesel.
 * Poté aplikace pro každé heslo postupnì zkouší hesla ze slovníku a pak hesla metodou brute force, dokud nenajde správné heslo nebo není pøekroèen èasový limit.
 * Pokud heslo není nalezeno, je vytvoøen záznam "not_cracked". Výsledky jsou pak zapsány do výstupního souboru v CSV formátu.
 * @author Stepan Lukes
 * @version 1.00.0000 04-28-2023
 * */

public class LamacHesel {
	
	// hlavní metoda
    public static void main(String[] args) {
    	// Nastavení promìnných pro soubory a maximální délky hesel
        String nazevSouboru = "password_database.csv";
        String osobniCislo = "A21B0625P";
        String slovnikovySoubor = "10000hesel.txt";
        int maxDelkaHesla = 6;
        long maxDelkaVeVterinach = 180;
        String nazevVystupnihoSouboru = "cracked_results_A21B0625P.csv";

     // Naètení slovníku hesel
        List<String> slovnik = prectiSlovnikovySoubor(slovnikovySoubor);

        // Naètení hashù hesel pro daného uživatele
        List<String> hasheHesel = prectiHeslovouDatabazy(nazevSouboru, osobniCislo);

        // Vytvoøení prázdného seznamu pro výsledky prolomení hesel
        List<LamacHeselVysledek> vysledky = new ArrayList<>();

        // Pro každý hash hesla v databázi se provádí prolomení hesla
        for (String hashHesla : hasheHesel) {
            String prolomeneHeslo = null; // inicializace promìnné pro výsledné prolomené heslo
            long pocetPokusu = 0; // inicializace promìnné pro poèet pokusù pøi prolomení hesla
            long zacatekMereni = System.nanoTime(); // zahájení mìøení èasu

            // Slovníkový útok - porovnávání hashù hesla s hesly ze slovníku
            for (String slovnikoveHeslo : slovnik) {
                pocetPokusu++; // zvýšení poètu pokusù o prolomení hesla
                if (hash(slovnikoveHeslo).equals(hashHesla)) {
                    prolomeneHeslo = slovnikoveHeslo; // nalezení shody hashù, heslo bylo prolomeno
                    break;
                }
            }

            // pokud nevyjde slovnikovy utok, pouzije se brute force
            
            if (prolomeneHeslo == null) {
                for (int i = 1; i <= maxDelkaHesla; i++) {
                	// Vypoèítá poèet kombinací pro danou délku hesla.
                	
                    long pocetKombinaci = (long) Math.pow(36, i);
                    
                    // Pokud se poèet kombinací vejde do rozsahu long, spustí se bruteforce útok.
                    if (pocetKombinaci < Long.MAX_VALUE - pocetPokusu) {
                    	// Generuje hesla pro danou délku i a testuje, zda-li se shodují s hashem hesla.
                        for (String heslo : generujHesla(i)) {
                            pocetPokusu++;
                            if (hash(heslo).equals(hashHesla)) {
                            	// Pokud se heslo shoduje s hashem hesla, nastaví se prolomeneHeslo a ukonèí se for cyklus.
                            	
                                prolomeneHeslo = heslo;
                                break;
                            }
                        }
                       
                    } 
                    
                    else {
                    	// Pokud je poèet kombinací pøíliš velký, zastaví se bruteforce útok a pokraèuje se s dalším
                        break;
                    }
                 // Pokud bylo heslo prolomeno, ukonèí se for cyklus.
                    if (prolomeneHeslo != null) {
                        break;
                    }
                }
                
            }
            
            // Mìøí celkovou délku bìhu programu
            long konecMereni = System.nanoTime();
            double delkaVeVterinach = (konecMereni - zacatekMereni) / 1e9;
            
         // Pokud heslo nebylo prolomeno, pøidá se výsledek "not_cracked" do výsledkù.
            if (prolomeneHeslo == null) {
                vysledky.add(new LamacHeselVysledek(hashHesla, "not_cracked", pocetPokusu, delkaVeVterinach));
                System.out.println("Heslo neprolomeno:" + " Hash uzivatele: " + hashHesla + ", not_cracked" + ", pocet pokusu: " + pocetPokusu + ", cas: " + delkaVeVterinach + "s" );
            } else {
            	// Pokud heslo bylo prolomeno, pøidá se prolomené heslo do výsledkù.
            	String trimmedPassword = prolomeneHeslo.trim();
                vysledky.add(new LamacHeselVysledek(hashHesla, trimmedPassword, pocetPokusu, delkaVeVterinach));
                System.out.println("Heslo prolomeno:" + " Hash uzivatele: " + hashHesla + ", heslo: " + trimmedPassword + ", pocet pokusu: " + pocetPokusu + ", cas: " + delkaVeVterinach + "s" );
            }

            
            // Pokud je pøekroèen èasový limit, pøidá se výsledek "not_cracked" do výsledkù a ukonèí se cyklus.
            if (delkaVeVterinach >= maxDelkaVeVterinach) {
            	vysledky.add(new LamacHeselVysledek(hashHesla, "not_cracked", pocetPokusu, delkaVeVterinach));
                break;
            }
            
        }
        
        // Zapíše výsledky do výstupního souboru.
        zapisVysledekDoSouboru(nazevVystupnihoSouboru, vysledky);
    }

    /**
     * Metoda pøeète slovníkový soubor a uloží jednotlivé øádky jako položky do seznamu.
     * 
     * @param nazevSouboru název souboru, který se má pøeèíst
     * @return seznam øetìzcù obsahujících jednotlivé øádky ze souboru
     */
    private static List<String> prectiSlovnikovySoubor(String nazevSouboru) {
        // Vytvoøení prázdného seznamu pro uložení øádkù ze souboru
        List<String> slovnik = new ArrayList<>();
        
        // Pokus o otevøení souboru pro ètení pomocí try-with-resources bloku pro automatické uzavøení readeru
        try (BufferedReader reader = new BufferedReader(new FileReader(nazevSouboru))) {
            // Promìnná pro ukládání naètené øádky
            String radka;
            
            // Ètení souboru øádek po øádku, dokud se nedosáhne konce souboru
            while ((radka = reader.readLine()) != null) {
                // Odstranìní pøípadných mezer z poèátku a konce naèteného øádku a pøidání do seznamu slovníku
                slovnik.add(radka.trim() + "\n");
            }
        } catch (IOException e) {
            // Pokud došlo k chybì pøi ètení souboru, vytiskne se výjimka
            e.printStackTrace();
        }
        
        // Vrácení seznamu slovníku
        return slovnik;
    }

              
    /**
     * Naète hesla uživatele s daným osobním èíslem ze souboru heslové databáze.
     *
     * @param nazevSouboru název souboru heslové databáze
     * @param osobniCislo osobní èíslo uživatele
     * @return seznam hashù hesel uživatele
     */
    private static List<String> prectiHeslovouDatabazy(String nazevSouboru, String osobniCislo) {
        // inicializace seznamu hashù hesel
        List<String> hasheHesel = new ArrayList<>();
        
        try (BufferedReader reader = new BufferedReader(new FileReader(nazevSouboru))) {
            String radka;
            // ètení souboru po øádcích
            while ((radka = reader.readLine()) != null) {
                // rozdìlení øádky na pole podle oddìlovaèe ","
                String[] pole = radka.trim().split(",");
                // naètení aktuálního uživatele a hashe jeho hesla
                String aktulaniUzivatel = pole[0];
                String hashHesla = pole[1];
                // porovnání aktuálního uživatele s hledaným osobním èíslem
                if (aktulaniUzivatel.equals(osobniCislo)) {
                    // pøidání hashe hesla do seznamu
                    hasheHesel.add(hashHesla);
                }
            }
        } catch (IOException e) {
            // zachycení výjimky a výpis chyby na standardní výstup
            e.printStackTrace();
        }
        // vrácení seznamu hashù hesel
        return hasheHesel;
    }

           
 // Metoda pro vytvoøení SHA-256 hash ze vstupního øetìzce
    private static String hash(String input) {
        try {
            // Vytvoøení instance MessageDigest objektu s algoritmem SHA-256
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            
            // Vypoèítání hash bytù pro vstupní øetìzec pomocí metody digest() z MessageDigest
            byte[] hashBytes = md.digest(input.getBytes(StandardCharsets.UTF_8));
            
            // Pøevod bytového pole na BigInteger s hodnotou 1 pro kladnost a hash byty jako druhý parametr
            BigInteger hashNum = new BigInteger(1, hashBytes);
            
            // Pøevod BigInteger na øetìzec v šestnáctkové soustavì a vrácení výsledku
            return hashNum.toString(16);
        } catch (NoSuchAlgorithmException e) {
            // Pokud algoritmus neexistuje, vypíše se stack trace a vrátí se hodnota null
            e.printStackTrace();
            return null;
        }
    }

     
    
     
    /**
     * Generuje seznam hesel dané délky.
     *
     * @param delka délka generovaných hesel
     * @return seznam hesel dané délky
     */
    private static List<String> generujHesla(int delka) {
        char[] znaky = "0123456789abcdefghijklmnopqrstuvwxyz".toCharArray();
        List<String> hesla = new ArrayList<>();

        // rekurzivnì generuje všechna hesla
        generujHeslaPomocnik(delka, znaky, "", hesla);

        return hesla;
    }

    /**
     * Rekurzivní funkce, která generuje všechna hesla dané délky.
     *
     * @param delka délka generovaných hesel
     * @param znaky seznam povolených znakù pro hesla
     * @param heslo aktuální heslo
     * @param hesla seznam všech vygenerovaných hesel
     */
    private static void generujHeslaPomocnik(int delka, char[] znaky, String heslo, List<String> hesla) {
        if (delka == 0) {
            // pøidá aktuální heslo do seznamu hesel
            hesla.add(heslo + "\n");
        } else {
            // rekurzivnì volá sebe sama pro každý možný znak až do dosažení délky hesla
            for (char c : znaky) {
                generujHeslaPomocnik(delka - 1, znaky, heslo + c, hesla);
            }
        }
    }

   
    
    /**
     * Zapisuje výsledky lámání hesel do souboru.
     * @param nazevSouboru název souboru, do kterého budou výsledky zapsány
     * @param vysledky seznam výsledkù, které mají být zapsány
     */
    private static void zapisVysledekDoSouboru(String nazevSouboru, List<LamacHeselVysledek> vysledky) {
        try (java.io.FileWriter writer = new java.io.FileWriter(nazevSouboru)) {
            // procházení výsledkù a zápis každého z nich na jednu øádku souboru
            for (LamacHeselVysledek vysledek : vysledky) {
                // sestavení øádky ve formátu "username_hash,cracked_password,num_tries,elapsed_time_seconds\n"
                String radka = vysledek.getUsernameHash() + "," + vysledek.getCrackedPassword() + ","
                        + vysledek.getNumTries() + "," + vysledek.getElapsedTimeSeconds() + "\n";
                // zápis øádky do souboru
                writer.write(radka);
            }
        } catch (IOException e) {
            // pokud dojde k chybì pøi zápisu, vypíše se chybové hlášení
            e.printStackTrace();
        }
    }

}

class LamacHeselVysledek {
    // deklarace soukromých instanèních promìnných
    private String hashUzivatele;
    private String prolomeneHeslo;
    private long pocetPokusu;
    private double casVeVterinach;

    // konstruktor tøídy LamacHeselVysledek, pøijímající nìkolik parametrù
    public LamacHeselVysledek(String hashUzivatele, String prolomeneHeslo, long pocetPokusu, double casVeVterinach) {
        // inicializace soukromých instanèních promìnných hodnotami z parametrù
        this.hashUzivatele = hashUzivatele;
        this.prolomeneHeslo = prolomeneHeslo;
        this.pocetPokusu = pocetPokusu;
        this.casVeVterinach = casVeVterinach;
    }

    // metoda pro získání hashe uživatelského jména
    public String getUsernameHash() {
        return hashUzivatele;
    }

    // metoda pro získání prolomeného hesla
    public String getCrackedPassword() {
        return prolomeneHeslo;
    }

    // metoda pro získání poètu pokusù
    public long getNumTries() {
        return pocetPokusu;
    }

    // metoda pro získání èasu, který byl potøeba pro prolomení hesla
    public double getElapsedTimeSeconds() {
        return casVeVterinach;
    }
}