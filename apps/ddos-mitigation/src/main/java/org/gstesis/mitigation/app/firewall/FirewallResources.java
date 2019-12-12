package org.gstesis.mitigation.app.firewall;

import java.util.ArrayList;
import java.util.Arrays;

/**
 * Firewall Resources Clas
 * @see Firewall
 */
public class FirewallResources {
    // Singleton
    private static FirewallResources ourInstance = new FirewallResources();

    private ArrayList<Long> sidAlertsIDSToServers;
    //  Variable
    private  ArrayList<String> ipVictimas;

    public static FirewallResources getInstance() {
        return ourInstance;
    }

    private FirewallResources() {
        sidAlertsIDSToServers = new ArrayList<>(Arrays.asList(
                1000005L, 1000041L, 1000047L, 1000046L, 1000044L,
                1000048L, 1000019L, 1000040L, 1000000L)); // La ultima es para test.

        ipVictimas = new ArrayList<>(Arrays.asList (
                "192.168.40.5" , "192.168.40.10", "192.168.40.11", "192.168.40.12",
                "192.168.40.13", "192.168.40.14", "192.168.40.15", "192.168.40.16",
                "192.168.40.17", "192.168.40.18", "192.168.40.19", "192.168.40.71",
                "192.168.40.72", "192.168.40.20", "192.168.40.21", "192.168.40.22",
                "192.168.40.23", "192.168.40.24", "192.168.40.25", "192.168.40.26",
                "192.168.40.27"));
    }

    public ArrayList<Long> getSidAlertsIDSToServers() {
        return sidAlertsIDSToServers;
    }

    public ArrayList<String> getIpVictimas() {
        return ipVictimas;
    }
}
