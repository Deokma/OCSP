package settings;

import java.io.*;
import java.util.Properties;
import java.util.Scanner;

public class CAClientSettings extends Settings {



    /*public CAClientSettings() throws IOException {
        Properties prop = readPropertiesFile();


    }*/

    public static void checkCAClientNameFile() throws IOException, ClassNotFoundException {
        readPropertiesFile();
        new File(caClientResourcesPath).mkdirs();
        new File(caClientPath).mkdirs();
        if (!new File(caClientResourcesPath + "subjectName.dat").exists()) {
            Scanner scanner = new Scanner(System.in);
            System.out.print("Enter username: ");
            caClientName = scanner.nextLine();
            ObjectOutputStream subjectNameOut =
                    new ObjectOutputStream(new FileOutputStream(caClientResourcesPath + "subjectName.dat"));
            subjectNameOut.writeObject(caClientName);
            subjectNameOut.close();
        } else {
            ObjectInputStream subjectNameIn =
                    new ObjectInputStream(new FileInputStream(caClientResourcesPath + "subjectName.dat"));
            caClientName = (String) subjectNameIn.readObject();
        }
    }
}
