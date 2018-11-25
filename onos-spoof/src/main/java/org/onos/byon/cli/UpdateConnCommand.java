package org.onos.byon.cli;

import com.sun.org.apache.regexp.internal.RE;
import org.apache.karaf.shell.commands.Command;

import org.onos.byon.DeviceService;
import org.onos.byon.NetworkService;
import org.onos.byon.ReactiveFwd;
import org.onosproject.cli.AbstractShellCommand;

/**
 * Created by hugo on 8/29/16.
 */
@Command(scope = "byon", name = "update-conn", description = "update device connectivity")
public class UpdateConnCommand extends AbstractShellCommand {

    @Override
    protected void execute() {

        //NetworkService networkService = get(NetworkService.class);
        DeviceService networkService = get(DeviceService.class);
        log.info("what is the heck");
        //DeviceService deviceService = get(DeviceService.class);

        try {
            networkService.updateConn();
            //deviceService.updateConn();
        } catch (Exception e) {
            log.warn("exception {}", e.toString());
            e.printStackTrace();
        }
    }
}
