import com.google.gson.*;

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.AbstractStringDataType;

import java.io.FileWriter;
import java.util.*;

public class ExportFunctions extends GhidraScript {

    @Override
    protected void run() throws Exception {

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        ReferenceManager refMgr = currentProgram.getReferenceManager();
        Listing listing = currentProgram.getListing();

        JsonArray functionsArray = new JsonArray();

        FunctionIterator funcs =
            currentProgram.getFunctionManager().getFunctions(true);

        int count = 0;

        for (Function f : funcs) {
            if (monitor.isCancelled()) break;

            println("[" + count + "] Decompiling: " + f.getName());

            JsonObject funcObj = new JsonObject();
            funcObj.addProperty("name", f.getName());
            funcObj.addProperty("address",
                "0x" + f.getEntryPoint().toString());
            funcObj.addProperty("size", f.getBody().getNumAddresses());
            funcObj.add("summary", JsonNull.INSTANCE);

            // --- Pseudocode via decompiler ---
            String pseudocode = null;
            try {
                DecompileResults res =
                    decomp.decompileFunction(f, 30, monitor);
                if (res != null
                        && res.decompileCompleted()
                        && res.getDecompiledFunction() != null) {
                    pseudocode = res.getDecompiledFunction().getC();
                }
            } catch (Exception e) {
                println("  WARN: decompile failed for " + f.getName());
            }

            if (pseudocode != null) {
                funcObj.addProperty("pseudocode", pseudocode);
            } else {
                funcObj.add("pseudocode", JsonNull.INSTANCE);
            }

            // --- Separate called functions into imports vs internal calls ---
            JsonArray importsArray = new JsonArray();
            JsonArray callsArray = new JsonArray();
            Set<String> seenImports = new LinkedHashSet<>();
            Set<String> seenCalls = new LinkedHashSet<>();

            for (Function called : f.getCalledFunctions(monitor)) {
                if (called.isThunk() || called.isExternal()) {
                    Function resolved = called.isThunk()
                        ? called.getThunkedFunction(true)
                        : called;
                    seenImports.add(resolved.getName());
                } else {
                    seenCalls.add(called.getName());
                }
            }

            for (String s : seenImports) importsArray.add(s);
            for (String s : seenCalls)   callsArray.add(s);

            funcObj.add("imports", importsArray);
            funcObj.add("calls", callsArray);

            // --- Extract referenced strings ---
            JsonArray stringsArray = new JsonArray();
            Set<String> seenStrings = new LinkedHashSet<>();
            AddressSetView body = f.getBody();
            AddressIterator addrIter =
                refMgr.getReferenceSourceIterator(body, true);

            while (addrIter.hasNext()) {
                Address fromAddr = addrIter.next();
                for (Reference ref : refMgr.getReferencesFrom(fromAddr)) {
                    Data data = listing.getDataAt(ref.getToAddress());
                    if (data != null
                            && data.getBaseDataType()
                                instanceof AbstractStringDataType) {
                        Object val = data.getValue();
                        if (val != null) {
                            seenStrings.add(val.toString());
                        }
                    }
                }
            }

            for (String s : seenStrings) stringsArray.add(s);
            funcObj.add("strings", stringsArray);

            functionsArray.add(funcObj);
            count++;
        }

        decomp.dispose();

        JsonObject root = new JsonObject();
        root.addProperty("program", currentProgram.getName());
        root.addProperty("function_count", count);
        root.add("functions", functionsArray);

        Gson gson = new GsonBuilder().setPrettyPrinting().create();

        String outputPath = "data\\functions.json";
        try (FileWriter writer = new FileWriter(outputPath)) {
            writer.write(gson.toJson(root));
        }

        println("Exported " + count + " functions to " + outputPath);
    }
}
