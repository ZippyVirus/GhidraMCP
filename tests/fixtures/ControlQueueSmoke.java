import com.lauriewired.ghidramcp.gui.GuiProgramProvider;
import com.lauriewired.ghidramcp.http.BackendHttpServer;
import ghidra.program.model.listing.Program;
import java.util.concurrent.CountDownLatch;

/** A controlled stand-in for an operation blocked by a modal GUI dialog. */
public class ControlQueueSmoke {
    public static void main(String[] args) throws Exception {
        CountDownLatch release=new CountDownLatch(1);
        GuiProgramProvider provider=new GuiProgramProvider(null) {
            public Program getProgram() {
                if(Thread.currentThread().getName().equals("GhidraMCP-Operations")) {
                    try {release.await();}
                    catch(InterruptedException e) {Thread.currentThread().interrupt();}
                }
                return null;
            }
        };
        BackendHttpServer server=new BackendHttpServer(provider);
        try {
            server.start(0);
            System.out.println("READY "+server.getPort());System.out.flush();
            System.in.read();release.countDown();
            System.in.read();
        } finally {server.stop();}
    }
}
