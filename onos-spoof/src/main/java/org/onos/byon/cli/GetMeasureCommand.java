package org.onos.byon.cli;

import org.onos.byon.NetworkService;
import org.apache.karaf.shell.commands.Argument;
import org.apache.karaf.shell.commands.Command;
import org.onosproject.cli.AbstractShellCommand;

/**
 * Created by hugo on 8/12/16.
 */
@Command(scope = "byon", name = "get-measure", description = "Add measurements to all devices")
public class GetMeasureCommand extends AbstractShellCommand {

    @Argument(index = 0, name = "index", description = "files that contains measurements",
            required = true, multiValued = false)
    String index = null;

    @Override
    protected void execute() {
        NetworkService networkService = get(NetworkService.class);
        networkService.getMeasure(Integer.parseInt(index));
    }
}
