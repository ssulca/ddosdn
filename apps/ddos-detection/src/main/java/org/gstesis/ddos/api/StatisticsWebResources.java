package org.gstesis.ddos.api;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.gstesis.ddos.app.AppError;
import org.gstesis.ddos.app.statistics.ChiResources;
import org.gstesis.ddos.app.statistics.StatisticsResources;
import org.onosproject.rest.AbstractWebResource;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Consumes;
import javax.ws.rs.Produces;
//import javax.ws.rs.PathParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.InputStream;
import java.util.ArrayDeque;
import java.util.concurrent.ConcurrentHashMap;

import static org.gstesis.ddos.app.statistics.StatisticsResources.DAY_BYTES;
import static org.gstesis.ddos.app.statistics.StatisticsResources.DAY_COUNT;
import static org.onlab.util.Tools.readTreeFromStream;


/**
 * Sample web resource.
 * implemntacion de los metodos.
 */
@Path("statistic")
public class StatisticsWebResources extends AbstractWebResource{

    private static final String VALUES = "values";
    private static final String BYTES  = "bytes";
    private static final String PKTS   = "pkts";
    private static final String[] chi_resources_tags_json = {
            "Timestamp","Cantidad de trafico observado - bytes", "Chi value - bytes",
            "Timestamp",
            "Cantidad de trafico observado - paquetes",
            "Chi value - paquetes"};

    /**
     * Get hello world greeting.
     *
     * @return 200 OK
     */
    @GET
    @Path("download")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getStatitics() {

        ObjectNode root;
        StatisticsResources statisticsResources;

        statisticsResources = StatisticsResources.getInstance();
        root = mapper().createObjectNode();

        statisticsResources.getDevExpectedMap().forEach((devId, values) -> {
            ObjectNode childNode = newObject(root,devId);

            ObjectNode ojnode = newObject(childNode,VALUES);
            ojnode.put(PKTS, values[DAY_COUNT]);
            ojnode.put(BYTES, values[DAY_BYTES]);
        });
        return ok(root).build();
    }

    /**
     * Set enabled IDS ips.
     *
     * @param request Ids Ip
     * @return 200 OK or 500 on error
     */

    @POST
    @Path("upload")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response addOrderByIp(InputStream request ) {
        ObjectNode root;
        //ObjectNode code;
        //AppError   err;
        ConcurrentHashMap<String, long[]> newMap = new ConcurrentHashMap<>();

        try {
            root = readTreeFromStream(mapper(), request);
            root.fieldNames().forEachRemaining(sk-> {
                AppError err = StatisticsResources.checkId(sk);
                if(!err.equals(AppError.SUCCESS)) {
                     throw new IllegalArgumentException("DevId: "+err.toString());
                }
                else {
                    root.path(sk).forEach(ck -> {

                        long[] valTmp = getValues((ObjectNode) ck);
                        AppError errChild = StatisticsResources.checkValues(valTmp);

                        if (!errChild.equals(AppError.SUCCESS)) {
                            throw new IllegalArgumentException("values: " + errChild.toString());
                        } else {
                            newMap.put(sk, valTmp);
                        }
                    });
                }
            });
            StatisticsResources.getInstance().externalSetDevExpectedMap(newMap);

            return Response.ok().build();
        }
        catch (Exception e){
            ObjectNode code = mapper().createObjectNode().put("Response",e.toString());
            return ok(code).build();
        }
    }

    /**
     * Get hello world greeting.
     *
     * @return 200 OK
     */
    @GET
    @Path("chi/values")
    @Produces(MediaType.APPLICATION_JSON)
    @SuppressWarnings("unchecked")
    public Response getChiSquare() {

        ObjectNode root;
        ArrayNode  arrayNode;
        ArrayDeque<String> values;

        root      = mapper().createObjectNode();
        arrayNode = mapper().createArrayNode();
        values    = ChiResources.getInstance().getChiSquareValues().clone();
        int size = values.size(); 
        ObjectNode parentNode = newObject(root, "statistic_values");
     
        for (int i = 0; i < (size - 5); i = i + 6) {
            //Grupos de datos por timestamps.
            ObjectNode childNode = newObject (parentNode, Integer.toString(i/6));
            //Campos.
            for (int j = 0; j < 6; j++){
                try{//Posibles excepciones, como index incorrectos.
                    arrayNode.add(values.removeFirst());
                    if (j != 3){//Timestamp debe figurar una sola vez.
                        //Agrego los distintos campos.
                        childNode.put (chi_resources_tags_json[j], arrayNode.get(arrayNode.size() - 1));
                    }
                }
                catch (Exception e){
                    e.printStackTrace();
                }
            }
        }

        return ok(root).build();
    }

    /**
     * get long [] object from ObjecNode
     * @param node ObjecNode
     * @return long [] or Excep
     */
    private long [] getValues(ObjectNode node){
        long [] values = new long[2];
        values[0] = node.get(PKTS).asLong();
        values[1] = node.get(BYTES).asLong();
        return values;
    }
}
