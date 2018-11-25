package org.onosproject.fwd;

import com.sun.org.apache.regexp.internal.RE;
import org.apache.karaf.shell.commands.Command;
import org.onosproject.cli.AbstractShellCommand;

/**
 * Created by onos on 5/22/17.
 */
@Command(scope = "onos", name = "end", description = "End Experiment")
public class EndCommand extends AbstractShellCommand {

    @Override
    protected void execute() {
        print("End the Raincoat Demo");
        //ReactiveForwarding.BEGIN = false;
        //ReactiveForwarding.ATTACK_TYPE = 0;
    }

}