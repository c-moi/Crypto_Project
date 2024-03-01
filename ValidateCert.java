import java.io.BufferedReader;
import java.io.FileReader;
import java.io.StringReader;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.io.IOException;
import java.io.FileInputStream;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.util.Date;


public class ValidateCert {

    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("Usage: validate-cert <format> <certfile>");
            return;
        }

        String format = args[0];
        String certFile = args[1];

        try {
            X509Certificate cert;

            if (format.equalsIgnoreCase("DER")) {
                // Charger le certificat depuis le fichier DER
                FileInputStream fis = new FileInputStream(certFile);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                cert = (X509Certificate) cf.generateCertificate(fis);
                fis.close();
            } else if (format.equalsIgnoreCase("PEM")) {
                // Charger le certificat depuis le fichier PEM
                String pemContent = readFile(certFile);
                byte[] derBytes = pemToDer(pemContent);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(derBytes));
            } else {
                System.out.println("Format de certificat non valide.");
                return;
            }

            // À ce stade, 'cert' contient le certificat chargé
            System.out.println("Certificat chargé avec succès :");

            // Extraire la clé publique du certificat auto-signé
            PublicKey publicKey = cert.getPublicKey();

            // Vérifier la signature à l'aide de la clé publique
            cert.verify(publicKey);

            System.out.println("La signature du certificat a été vérifiée avec succès.");

            // Afficher le sujet et l'émetteur du certificat
            System.out.println("Sujet : " + cert.getSubjectX500Principal());
            System.out.println("Émetteur : " + cert.getIssuerX500Principal());


            // Vérifier l'extension KeyUsage
            boolean[] keyUsage = cert.getKeyUsage();
            if (keyUsage != null && keyUsage.length > 0) {
                System.out.println("Extension KeyUsage présente.");
                // À ce stade, tu peux ajouter des vérifications spécifiques sur les valeurs de KeyUsage si nécessaire
            } else {
                System.out.println("Extension KeyUsage non présente.");
            }

            // Vérifier la période de validité
            cert.checkValidity();
            System.out.println("Certificat valide jusqu'au : " + cert.getNotAfter());

            Date now = new Date();
            if (now.before(cert.getNotBefore())) {
                System.out.println("Le certificat n'est pas encore valide.");
            } else if (now.after(cert.getNotAfter())) {
                System.out.println("Le certificat a expiré.");
            } else {
                System.out.println("Le certificat est valide.");
            }

            // Maintenant, tu peux passer à la prochaine étape
            // Extraire l'algorithme de signature du certificat
            String algorithm = cert.getSigAlgName();
            System.out.println("Algorithme de signature : " + algorithm);

            // Vérifier la signature du certificat
            byte[] signature = cert.getSignature();
            Signature sig = Signature.getInstance(algorithm);
            sig.initVerify(publicKey);
            sig.update(cert.getTBSCertificate());
            boolean verified = sig.verify(signature);
            if (verified) {
                System.out.println("La signature du certificat est valide.");
            } else {
                System.out.println("La signature du certificat est invalide.");
            }
            // Maintenant, tu peux passer à la prochaine étape
            // N'hésite pas si tu as des questions ou si tu veux continuer.
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String readFile(String filename) throws IOException {
        StringBuilder contentBuilder = new StringBuilder();
        BufferedReader br = new BufferedReader(new FileReader(filename));
        String line;
        while ((line = br.readLine()) != null) {
            contentBuilder.append(line).append("\n");
        }
        br.close();
        return contentBuilder.toString();
    }

    private static byte[] pemToDer(String pemContent) {
        StringReader reader = new StringReader(pemContent);
        BufferedReader bufferedReader = new BufferedReader(reader);
        StringWriter writer = new StringWriter();
        BufferedWriter bufferedWriter = new BufferedWriter(writer);
        String line;
        boolean readingStarted = false;
        try {
            while ((line = bufferedReader.readLine()) != null) {
                if (line.contains("BEGIN CERTIFICATE")) {
                    readingStarted = true;
                } else if (line.contains("END CERTIFICATE")) {
                    readingStarted = false;
                } else if (readingStarted) {
                    bufferedWriter.write(line);
                }
            }
            bufferedReader.close();
            bufferedWriter.close();
            return Base64.getDecoder().decode(writer.toString());
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
}
