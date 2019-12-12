package org.gstesis.mitigation.app.server;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;

import org.gstesis.mitigation.app.AppError;
import org.gstesis.mitigation.app.alert.RegistroDeAlerta;
import org.gstesis.mitigation.app.firewall.Firewall;

import org.slf4j.Logger;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * Clase SocketServerListener.
 * Crea un clientSocket y un serverSocket. El socket server acepta
 * conexión del socket cliente. Puede aceptar multiples conexiones.
 *
 * @see java.lang.Runnable
 */
public class SocketServerListener implements Runnable {

    // Puerto que escucha el socket server.
    private static final int PORT             = 11991;
    // Nro. maximo de clientes IDS.
    private static final int NUM_CLIENTES_MAX = 12;

    private final Logger log = getLogger(getClass()); // Logger.

    private static HashSet<RegistroDeAlerta> listaDeAlertas = new HashSet<>();

    private Firewall        firewall;
    private ServerSocket    serverSocket;
    private ArrayList<Long> sidAlertsIDSToServers;

    /**
     * Contructor
     * @param firewall Firewall
     */
    public SocketServerListener (Firewall firewall){
        this.firewall              = firewall;
        this.sidAlertsIDSToServers = firewall.getSidsIDSToServers();
    }

    /**
     * Run socket Server listener Max 5 Conections
     */
    @Override
    public void run() {
        log.info ("Receiving thread started...");
        // Run connection
        logSocketServer();
    }

    /**
     * Método logSocketServer. Crea un socketServer y acepta conexiones de
     * multiples clientes. En caso de excepción cierra los buffers y los
     * sockets.
     */
    private void logSocketServer() {

        Socket          clientSocket;
        ExecutorService executor;

        executor = null;
        try {
            serverSocket = new ServerSocket();
            serverSocket.setReuseAddress(true);
            serverSocket.bind(new InetSocketAddress(PORT));
            // Utilizacion de thread pool executor
            executor     = Executors.newFixedThreadPool(NUM_CLIENTES_MAX);
            // Create new Connections RUN(_main_)
            while (!Thread.currentThread().isInterrupted()) {
                log.info ("SocketServerListener: Waiting for client...");
                // Aceptar nuevo cliente
                clientSocket = serverSocket.accept();

                log.info ("SocketServerListener: Accepted client={}",
                        clientSocket.getRemoteSocketAddress().toString());

                // Correr nuevo thread que procesa alertas y llama funciones del firewall.
                executor.execute(
                        new Connection(clientSocket, this.firewall, this.sidAlertsIDSToServers,
                                listaDeAlertas));
            }// while (!Thread.currentThread().isInterrupted())
        }
        catch (IOException e) {
            log.error ("{}::ServerSocket listening error from port={} in localhost",
                    AppError.LOCKED, PORT);
        }
        catch (RejectedExecutionException e){
            log.error("{}::posible limite maximo de exec", AppError.CONCURRENT_ERROR);
        }
        catch (Exception e) {
            log.info("{}: Exception = {}", e.toString(), AppError.UNKNOWN);
        }
        finally { /* Cierra Socket Listener y todos los sockets clientes. */
            try {
                if (serverSocket != null) {
                    serverSocket.close();
                    log.info ("DpiResultListener: stopped, Server closed ");
                }
                if(executor != null){
                    executor.shutdown();
                }
            }
            catch (Exception e) {
                log.error ("SocketServerListener: stopped: " +
                        "Socket closing error, exception={}", e.toString());
            }
        } // finally
    }// logSocketServer()
} //class SockerServerListener
