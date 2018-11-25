package org.onosproject.fwd;

import org.apache.karaf.shell.commands.Command;
import org.onosproject.cli.AbstractShellCommand;

/**
 * Created by onos on 5/21/17.
 */
@Command(scope = "onos", name = "begin",
        description = "Begin Raincoat Demo")
public class BeginCommand extends AbstractShellCommand {

    @Override
    protected void execute() {
        print("Begin the Raincoat Demo");
        ReactiveForwarding.BEGIN = true;
    }

}
