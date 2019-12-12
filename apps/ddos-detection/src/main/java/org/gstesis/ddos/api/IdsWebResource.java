/*
 * Copyright 2019-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.gstesis.ddos.api;

import org.gstesis.ddos.app.processor.IdsResources;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.onosproject.rest.AbstractWebResource;
import org.onlab.packet.IpAddress;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.DELETE;
import javax.ws.rs.Path;
import javax.ws.rs.Consumes;
import javax.ws.rs.Produces;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import java.util.Set;


/**
 * Sample web resource.
 * implemntacion de los metodos.
 */
@Path("ids")
public class IdsWebResource extends AbstractWebResource  {

    private static final String IP = "ip";

    /**
     * Get hello world greeting.
     *
     * @return 200 OK
     */
    @GET
    @Path("ips")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getOrders() {
        ObjectNode     node;
        ArrayNode      ipArray;
        Set<IpAddress> idsResources;


        idsResources     = IdsResources.getInstance().getIpAddressSet();
        node             = mapper().createObjectNode();
        ipArray          = mapper().createArrayNode();

        idsResources.forEach(ipAddress -> {
            ipArray.add(ipAddress.toString()); // Add IDS ips
        });
        node.putArray(IP).addAll(ipArray);     // add Array to Object

        return ok(node).build();
    }
    
    /**
     * Set enabled IDS ips.
     *
     * @param component Ids Ip
     * @return 200 OK or 500 on error
     */

    @POST
    @Path("ip/{component}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response addOrderByIp(@PathParam("component") String component) {

        boolean        response;
        ObjectNode     node;
        IdsResources   idsResources;

        idsResources = IdsResources.getInstance();

        response = idsResources.addIpAddres(component.trim());

        node = mapper().createObjectNode().put("Response", response);

        return ok(node).build();
    }

    @DELETE
    @Path("ip/{component}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response deleteOrderById(@PathParam("component") String component) {
        boolean        response;
        ObjectNode     node;
        IdsResources   idsResources;

        idsResources = IdsResources.getInstance();

        response = idsResources.delIpAddres(component.trim());

        node = mapper().createObjectNode().put("Response", response);

        return ok(node).build();
    }
}
