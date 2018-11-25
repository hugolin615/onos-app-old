package org.onos.byon.cli;

import org.onos.byon.NetworkService;
import org.apache.karaf.shell.commands.Argument;
import org.apache.karaf.shell.commands.Command;
import org.onosproject.cli.AbstractShellCommand;

/**
 * Created by hugo on 8/12/16.
 */
@Command(scope = "byon", name = "update-measure", description = "Add measurements to all devices")
public class UpdateMeasureCommand extends AbstractShellCommand {

    @Override
    protected void execute() {
        NetworkService networkService = get(NetworkService.class);
        try {
            networkService.updateMeasure();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
