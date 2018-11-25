package org.onosproject.fwd;

import org.apache.karaf.shell.commands.Argument;
import org.apache.karaf.shell.commands.Command;
import org.onosproject.cli.AbstractShellCommand;

/**
 * Created by onos on 5/21/17.
 */
@Command(scope = "onos", name = "begin", description = "Begin Experiment")
public class BeginCommand extends AbstractShellCommand {


    @Argument(index = 0, name = "attackType",
            description = "Type of attacks to simulate",
            required = true, multiValued = false)
    String attackType = null;


    @Override
    protected void execute() {
        int result = Integer.parseInt(attackType);
        if ( result <=0 || result > 4){
            print("Unsupported attack type.");
            return;
        }
        print("Begin simulating attack");
        //ReactiveForwarding.BEGIN = true;
        //ReactiveForwarding.ATTACK_TYPE = result;
    }

}
