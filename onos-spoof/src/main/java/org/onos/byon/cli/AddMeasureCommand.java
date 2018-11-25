package org.onos.byon.cli;

import org.apache.karaf.shell.commands.Argument;
import org.apache.karaf.shell.commands.Command;
import org.onos.byon.NetworkService;
import org.onosproject.cli.AbstractShellCommand;

/**
 * CLI to add a host to a network.
 */
@Command(scope = "byon", name = "add-measure", description = "Add measurements to all devices")
public class AddMeasureCommand extends AbstractShellCommand {

    @Argument(index = 0, name = "fileName", description = "files that contains measurements",
            required = true, multiValued = false)
    String fileName = null;

    @Override
    protected void execute() {
        NetworkService networkService = get(NetworkService.class);
        networkService.addMeasure(fileName);
    }
}