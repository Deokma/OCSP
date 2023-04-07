package ocsp;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class OCSPServer {
    public static void main(String[] args) throws IOException {
        int port = 8888; // Порт, который будем слушать

        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("Сервер запущен на порту " + port);

        while (true) {
            Socket clientSocket = serverSocket.accept(); // Ждем подключения клиента
            System.out.println("Подключился клиент " + clientSocket.getInetAddress());

            // канал записи в сокет
            DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream());
            System.out.println("DataOutputStream created");

            // канал чтения из сокета
            DataInputStream in = new DataInputStream(clientSocket.getInputStream());
            System.out.println("DataInputStream created");

            String entry = in.readUTF();

            System.out.println("READ from client message - " + entry);

            if (entry.equalsIgnoreCase("quit")) {
                System.out.println("Client initialize connections suicide ...");
                out.writeUTF("Server reply - " + entry + " - OK");
                out.flush();
                break;
            }

            // Обрабатываем запрос клиента в новом потоке
            new Thread(() -> {
                String response = handleRequest(entry);
                try {
                    // Отправляем ответ клиенту
                    out.writeUTF(response);
                    out.flush();
                } catch (IOException e) {
                    e.printStackTrace();
                } finally {
                    try {
                        // Закрываем соединение с клиентом
                        clientSocket.close();
                        System.out.println("Соединение с клиентом " + clientSocket.getInetAddress() + " закрыто");
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }).start();
        }

    }

    public static String handleRequest(String request) {
        // Обработка запроса клиента
        if (request.equalsIgnoreCase("hello")) {
            return "Привет, клиент!";
        } else {
            return "Я не знаю, что ответить на это сообщение";
        }
    }
}
