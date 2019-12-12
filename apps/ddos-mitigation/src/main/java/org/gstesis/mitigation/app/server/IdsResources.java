package org.gstesis.mitigation.app.server;

import org.onlab.packet.IpAddress;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import org.gstesis.mitigation.app.AppError;

import org.slf4j.Logger;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * Ids resources
 * @see org.gstesis.mitigation.api.IdsWebResource
 */
public class IdsResources {
    private static IdsResources ourInstance = new IdsResources();
    private final Logger log = getLogger(getClass());

    ////////////// Cuncurrent Variables /////////////////
    private final ReadWriteLock readWriteLock = new ReentrantReadWriteLock();
    private final Lock readLock               = readWriteLock.readLock();
    private final Lock writeLock              = readWriteLock.writeLock();

    private Set<IpAddress> ipAddressSet;

    /**
     * our isntance
     */
    private IdsResources() {
        this.ipAddressSet = new HashSet<>(Arrays.asList(
                IpAddress.valueOf("192.168.12.3"),
                IpAddress.valueOf("192.168.13.3"),
                IpAddress.valueOf("192.168.14.3"),
                IpAddress.valueOf("192.168.15.3")));
    }

    public static IdsResources getInstance() {
        return ourInstance;
    }

    public Set<IpAddress> getIpAddressSet() {
        readLock.lock();
        try {
            if (this.ipAddressSet.isEmpty()) {
                this.ipAddressSet = new HashSet<>(Arrays.asList(
                        IpAddress.valueOf("192.168.12.3"),
                        IpAddress.valueOf("192.168.13.3"),
                        IpAddress.valueOf("192.168.14.3"),
                        IpAddress.valueOf("192.168.15.3")));
            }
            return ipAddressSet;
        }
        catch (Exception e){
            log.error("Get IDS ips{}", AppError.CONCURRENT_ERROR);
            return null;
        }
        finally {
            readLock.unlock();
        }
    }

    /**
     * Add IDS ip addres
     * @param ip4AddrString String ip Address
     * @return true, if it is added, false if it is not added
     */
    public synchronized boolean addIpAddres(String ip4AddrString) {
        IpAddress ipAddres;
        writeLock.lock();
        try {
            ipAddres = IpAddress.valueOf(ip4AddrString);
            return this.ipAddressSet.add(ipAddres);
        }
        catch (IllegalArgumentException e){
            log.error("Add IDS ip: Argument not valid :{}", ip4AddrString);
            return false;
        }
        catch (Exception e){
            log.error("{}", AppError.CONCURRENT_ERROR);
            return false;
        }
        finally {
            writeLock.unlock();
        }
    }

    /**
     * Del addres from IP
     * @param ip4AddrString, String ip Address
     * @return true, if it is removed, false if it is not removed
     */
    public synchronized boolean delIpAddres(String ip4AddrString){
        IpAddress ipAddres;
        writeLock.lock();
        try {
            ipAddres = IpAddress.valueOf(ip4AddrString);
            return this.ipAddressSet.remove(ipAddres);
        }
        catch (IllegalArgumentException e){
            log.error("Add IDS ip: Argument not valid :{}", ip4AddrString);
            return false;
        }
        catch (Exception e){
            log.error("{}", AppError.CONCURRENT_ERROR);
            return false;
        }
        finally {
            writeLock.unlock();
        }
        
    }
}
