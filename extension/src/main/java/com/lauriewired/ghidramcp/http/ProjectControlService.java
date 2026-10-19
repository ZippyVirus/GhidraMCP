package com.lauriewired.ghidramcp.http;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import com.google.gson.*;
import com.lauriewired.ghidramcp.gui.GuiProgramProvider;
import com.lauriewired.ghidramcp.core.McpException;
import ghidra.app.services.ProgramManager;
import ghidra.app.script.*;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import generic.jar.ResourceFile;
import java.awt.Component;
import java.awt.Container;
import java.awt.Dialog;
import java.awt.Window;
import javax.swing.*;

/** Project-wide access to the live GUI project; no headless shadow copies. */
public final class ProjectControlService {
    private final GuiProgramProvider provider;
    private final AtomicBoolean busy = new AtomicBoolean();
    private volatile Map<String,Object> job = Map.of("state","idle");
    public ProjectControlService(GuiProgramProvider provider) { this.provider=provider; }
    private PluginTool tool() { return provider.getTool(); }
    private Project project() {
        Project p=tool().getProject();
        if(p==null)throw new IllegalStateException("No GUI project is open.");
        return p;
    }
    private void available(Request q) {
        expectedProject(q);
        if(busy.get())throw new IllegalStateException("A project job is running; wait for the job before editing.");
    }
    private void expectedProject(Request q) {
        if(!project().getName().equals(q.required("project")))
            throw new McpException("PROJECT_MISMATCH",409,"The active project differs from the requested project. Nothing changed.");
    }
    private DomainFile file(String path) {
        if(!path.startsWith("/") || path.contains(".."))
            throw new IllegalArgumentException("Use an absolute project program path.");
        DomainFile f=project().getProjectData().getFile(path);
        if(f==null || !Program.class.isAssignableFrom(f.getDomainObjectClass()))
            throw new IllegalArgumentException("No program at "+path);
        return f;
    }
    private Program open(String path) {
        try {
            Program p=(Program)file(path).getDomainObject(this,false,false,TaskMonitor.DUMMY);
            try {
                if(ghidra.program.util.GhidraProgramUtilities.shouldAskToAnalyze(p))
                    ghidra.program.util.GhidraProgramUtilities.markProgramNotToAskToAnalyze(p);
                tool().getService(ProgramManager.class).openProgram(p,ProgramManager.OPEN_CURRENT);
                return p;
            } finally {p.release(this);}
        } catch(Exception e) {throw new IllegalStateException("Cannot open "+path,e);}
    }
    private void collect(DomainFolder folder,List<Map<String,Object>> out) {
        for(DomainFile f:folder.getFiles())
            out.add(Map.of("path",f.getPathname(),"type",f.getContentType(),"open",f.isOpen()));
        for(DomainFolder child:folder.getFolders())collect(child,out);
    }
    public Object list() {
        return provider.runWrite(()-> {
            var rows=new ArrayList<Map<String,Object>>();
            collect(project().getProjectData().getRootFolder(),rows);
            return Map.of("project",project().getName(),"programs",rows,"job",job,"location",project().getProjectLocator().toString());
        });
    }
    public Object select(Request q) {
        return provider.runWrite(()-> {
            available(q);Program p=open(q.required("path"));
            tool().getService(ProgramManager.class).setCurrentProgram(p);
            return Map.of("path",p.getDomainFile().getPathname(),"name",p.getName());
        });
    }
    public Object patch(Request q) {
        return provider.runWrite(()-> {
            available(q);Program p=open(q.required("path"));
            if(!p.canLock())throw new McpException("PROGRAM_BUSY",409,"Wait for the active analysis/edit transaction before patching.");
            JsonArray edits=JsonParser.parseString(q.required("changes")).getAsJsonArray();
            if(edits.isEmpty() || edits.size()>256)throw new IllegalArgumentException("Use 1-256 edits per transaction.");
            List<long[]> ranges=new ArrayList<>();
            try {
                for(var element:edits) {
                    JsonObject e=element.getAsJsonObject();
                    var a=p.getAddressFactory().getAddress(e.get("address").getAsString().replaceFirst("^0[xX]", ""));
                    byte[] old=HexFormat.of().parseHex(e.get("old").getAsString().replace(" ",""));
                    byte[] next=HexFormat.of().parseHex(e.get("new").getAsString().replace(" ",""));
                    if(a==null || old.length==0 || old.length!=next.length || old.length>4096)
                        throw new IllegalArgumentException("Invalid address or unequal/oversized edit.");
                    long start=a.getOffset(),end=start+old.length;
                    for(long[] r:ranges)if(start<r[1] && r[0]<end)throw new IllegalArgumentException("Overlapping edits.");
                    ranges.add(new long[]{start,end});
                    byte[] actual=new byte[old.length];
                    if(p.getMemory().getBytes(a,actual)!=old.length || !Arrays.equals(actual,old))
                        throw new McpException("EXPECTED_BYTES_MISMATCH",409,"Expected bytes differ at "+a+". Nothing changed.");
                }
                int tx=p.startTransaction("Guarded GhidraMCP byte edits");boolean ok=false;
                try {
                    FlatProgramAPI api=new FlatProgramAPI(p,TaskMonitor.DUMMY);
                    for(var element:edits) {
                        JsonObject e=element.getAsJsonObject();
                        var a=p.getAddressFactory().getAddress(e.get("address").getAsString().replaceFirst("^0[xX]", ""));
                        byte[] next=HexFormat.of().parseHex(e.get("new").getAsString().replace(" ",""));
                        boolean code=e.has("disassemble") && e.get("disassemble").getAsBoolean();
                        if(code)api.clearListing(a,a.add(next.length-1));
                        p.getMemory().setBytes(a,next);
                        if(code)api.disassemble(a);
                    }
                    ok=true;
                } finally { p.endTransaction(tx,ok); }
                return Map.of("path",p.getDomainFile().getPathname(),"changes",edits.size(),"saved",false);
            } catch(McpException e) { throw e; }
            catch(Exception e) { throw new IllegalStateException(e.getMessage(),e); }
        });
    }
    public Object save(Request q) {
        return provider.runWrite(()-> {
            available(q);int saved=0;
            try {
                Program p=open(q.required("path"));
                if(!p.canLock())throw new McpException("PROGRAM_BUSY",409,"The program has an active transaction; retry saving after analysis/editing settles.");
                if(p.isChanged()) {p.save("Save GhidraMCP edits",TaskMonitor.DUMMY);saved++;}
                return Map.of("saved_programs",saved);
            } catch(McpException e) {throw e;}
            catch(Exception e) {throw new IllegalStateException(e);}
        });
    }
    public Object start(Request q) {
        Project context=provider.runWrite(()-> {available(q);return project();});
        String action=q.required("action");
        if(!action.equals("analyze") && !action.equals("script"))
            throw new IllegalArgumentException("Action must be analyze or script.");
        Program target=action.equals("analyze")?provider.runWrite(()->open(q.required("path"))):provider.getProgram();
        if(target!=null)target.addConsumer(this);
        if(!busy.compareAndSet(false,true)) {
            if(target!=null)target.release(this);
            throw new IllegalStateException("A project job is already running.");
        }
        String id=UUID.randomUUID().toString();
        job=Map.of("state","running","action",action,"id",id);
        new Thread(()-> {
            StringWriter log=new StringWriter();
            try {
                if(action.equals("analyze")) {
                    int before=target.getFunctionManager().getFunctionCount();
                    new FlatProgramAPI(target,TaskMonitor.DUMMY).analyzeAll(target);
                    long deadline=System.nanoTime()+5_000_000_000L;
                    while(!target.canLock() && System.nanoTime()<deadline)Thread.sleep(25);
                    job=Map.of("state","complete","action",action,"id",id,
                        "functions_before",before,"functions_after",target.getFunctionManager().getFunctionCount(),
                        "ready_to_save",target.canLock(),"saved",false);
                } else {
                    ResourceFile source=new ResourceFile(q.required("script_path"));
                    if(!source.isFile() || GhidraScriptUtil.findSourceDirectoryContaining(source)==null)
                        throw new IllegalArgumentException("Script must be in a registered Ghidra script directory.");
                    var scriptProvider=GhidraScriptUtil.getProvider(source);
                    if(scriptProvider==null)throw new IllegalArgumentException("Unsupported script type.");
                    GhidraScript runner=scriptProvider.getScriptInstance(source,new PrintWriter(log,true));
                    String args=q.optional("arguments");
                    runner.setScriptArgs(args==null?new String[0]:new Gson().fromJson(args,String[].class));
                    GhidraState state=provider.runWrite(()-> {
                        if(project()!=context)throw new IllegalStateException("The GUI project changed before the script started.");
                        return new GhidraState(tool(),context,target,null,null,null);
                    });
                    runner.execute(state,TaskMonitor.DUMMY,new PrintWriter(log,true));
                    job=Map.of("state","complete","action",action,"id",id,"log",log.toString());
                }
            } catch(Throwable e) {
                job=Map.of("state","failed","action",action,"id",id,"error",e.toString(),"log",log.toString());
            } finally {
                if(target!=null)target.release(this);
                busy.set(false);
            }
        },"GhidraMCP-Project-"+action).start();
        return Map.of("state","running","action",action,"id",id);
    }
    public Object status() { return job; }

    private void dialogContents(Container container, java.util.List<String> text, java.util.List<JButton> buttons) {
        for(Component c:container.getComponents()) {
            if(!c.isVisible())continue;
            if(c instanceof JButton b)buttons.add(b);
            else if(c instanceof JLabel label && label.getText()!=null)text.add(label.getText());
            else if(c instanceof JTextArea area)text.add(area.getText());
            else if(c instanceof JEditorPane pane)text.add(pane.getText());
            else if(c instanceof docking.widgets.MultiLineLabel label)text.add(label.getLabel());
            if(c instanceof Container nested)dialogContents(nested,text,buttons);
        }
    }
    public Object dialogs() {
        return provider.runWrite(()-> {
            project();var result=new ArrayList<Map<String,Object>>();
            for(Window window:Window.getWindows())if(window instanceof Dialog d && d.isShowing()) {
                var text=new ArrayList<String>();var buttons=new ArrayList<JButton>();
                dialogContents(d,text,buttons);
                result.add(Map.of("id",Integer.toHexString(System.identityHashCode(d)),"title",d.getTitle(),
                    "modal",d.isModal(),"text",text,"buttons",buttons.stream().filter(JButton::isShowing)
                        .map(b->Map.of("text",String.valueOf(b.getText()),"enabled",b.isEnabled())).toList()));
            }
            return Map.of("dialogs",result);
        });
    }
    public Object respond(Request q) {
        return provider.runWrite(()-> {
            expectedProject(q);String id=q.required("id"),choice=q.required("button");
            for(Window window:Window.getWindows())if(window instanceof Dialog d && d.isShowing()
                && Integer.toHexString(System.identityHashCode(d)).equals(id)) {
                var text=new ArrayList<String>();var buttons=new ArrayList<JButton>();dialogContents(d,text,buttons);
                var matches=buttons.stream().filter(b->b.isShowing() && b.isEnabled() && choice.equals(b.getText())).toList();
                if(matches.size()!=1)throw new IllegalArgumentException("Choose one enabled button exactly as listed by ghidra_dialogs.");
                SwingUtilities.invokeLater(()->matches.get(0).doClick());
                return Map.of("dialog",id,"button",choice,"queued",true);
            }
            throw new IllegalArgumentException("Dialog is no longer visible; inspect dialogs again.");
        });
    }
}
