package org.gstesis.ddos.app.statistics;

import java.util.ArrayDeque;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Singleton: Chi Squre Resources used to monitoring for API
 * @see org.gstesis.ddos.api.StatisticsWebResources
 */
public class ChiResources {
    private static final int CANT_VALORES_GRAFICOS = 11;
    private static final int CANT_VALORES_ARRAY_DEQUE = CANT_VALORES_GRAFICOS * 6;

    private static ChiResources ourInstance = new ChiResources();

    private ArrayDeque<String> chiSquareValues;
    ////////////// Cuncurrent Variables /////////////////
    private final ReadWriteLock readWriteLock = new ReentrantReadWriteLock();
    private final Lock readLock  = readWriteLock.readLock();
    private final Lock writeLock = readWriteLock.writeLock();

    /**
     * Singleton constucton
     */
    private ChiResources() {
        this.chiSquareValues = new ArrayDeque<>(CANT_VALORES_ARRAY_DEQUE);

    }

    /**
     * ChiResources get instance
     * @return unique ChiResources object
     */
    public static ChiResources getInstance() {
        return ourInstance;
    }

    /**
     * return chi saqute calculated
     * @return ArrayDeque<String>
     */
    public ArrayDeque<String> getChiSquareValues() {
        readLock.lock();
        try {
            return chiSquareValues;
        }
        catch (Exception e){
            return null;
        }
        finally {
            readLock.unlock();
        }
    }

    /**
     * types
     * @param valor String con informacion (chi-cuadrado paquetes,
     *              chi-cuadrado bytes, timestamp)
     */
    public void setChiSquareValues(String valor) {
        writeLock.lock();
        try {
            this.chiSquareValues.addFirst(valor);
            if (chiSquareValues.size()>(CANT_VALORES_ARRAY_DEQUE)){
                chiSquareValues.removeLast();
                
            }
        }
        catch (Exception e){
            // not set
        }
        finally {
            writeLock.unlock();
        }
    }
}
