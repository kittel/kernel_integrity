#include <cstring>
#include <iostream>

#define MODULE_BASE_DIR "/home/kittel/projekte/insight/images/symbols/ubuntu-13.04-64-server/3.8.13-19-generic-dbg"
#define KERNEL_IMAGE "/home/kittel/projekte/insight/images/symbols/ubuntu-13.04-64-server/linux-3.8.0/vmlinux"
#define MEM_SAVE_DIR "/home/kittel/projekte/insight/memdump/"






void PageVerifier::applySmpLocks(SegmentInfo info, elfParseData &context)
{
    bool doPrint = false;
    //if(context.type == Detect::KERNEL_CODE) doPrint = true;

    char * fileContent = context.fileContent;

    //if(context.currentModule.member("name").toString().compare("\"e1000\"") == 0) doPrint = false;

    qint32 * smpLocksStart = (qint32 *) info.index;;
    qint32 * smpLocksStop = (qint32 *) (info.index + info.size);

    Instance x86_capability = _sym.factory().
            findVarByName("boot_cpu_data")->
            toInstance(_vmem, BaseType::trLexical, ksAll).
            member("x86_capability");

    unsigned char lock = 0;

    if (!((x86_capability.arrayElem(X86_FEATURE_UP / 32).toUInt32() >> (X86_FEATURE_UP % 32)) & 0x1))
    {
        /* turn lock prefix into DS segment override prefix */
        if(doPrint) std::cout << " No smp" << std::endl;
        lock = 0x3e;

    }
    else
    {
        /* turn DS segment override prefix into lock prefix */
        if(doPrint) std::cout << " Smp !" << std::endl;
        lock = 0xf0;
    }


    uint64_t smpLockSegmentInMem = 0;
    uint64_t textSegmentInMem = 0;

    if(context.type == Detect::KERNEL_CODE)
    {
        smpLockSegmentInMem = findElfSegmentWithName(fileContent, ".smp_locks").address;
        textSegmentInMem = findElfSegmentWithName(fileContent, ".text").address;
    }
    else if(context.type == Detect::MODULE)
    {
        smpLockSegmentInMem = findMemAddressOfSegment(context, ".smp_locks");
        textSegmentInMem = findMemAddressOfSegment(context, ".text");
    }

    bool addSmpEntries = false;
    if(context.smpOffsets.size() == 0) addSmpEntries = true;
    

    for(qint32 * poff = smpLocksStart; poff < smpLocksStop ; poff++)
    {
        uint8_t *ptr = (uint8_t *)poff + *poff;


        //Adapt offset in ELF
        qint32 offset = (info.index - context.textSegment.index) - (smpLockSegmentInMem - textSegmentInMem);
        ptr -= offset;

        if(doPrint) std::cout << hex << "Applying SMP reloc @ " << (uint64_t) ptr << " ( " << (uint8_t) *ptr << " ) " << dec << std::endl;
        *ptr = lock;

        if (addSmpEntries) context.smpOffsets.insert((uint64_t) ptr - (uint64_t) context.textSegment.index);
    }
}

void PageVerifier::applyMcount(SegmentInfo info, PageVerifier::elfParseData &context, QByteArray &segmentData){
    //See ftrace_init_module in kernel/trace/ftrace.c

    uint64_t * mcountStart = (uint64_t *) info.index;;
    uint64_t * mcountStop = (uint64_t *) (info.index + info.size);

    uint64_t textSegmentInMem = 0;

    if(context.type == Detect::KERNEL_CODE)
    {
        textSegmentInMem = context.textSegment.address;
    }
    else if(context.type == Detect::MODULE)
    {
        textSegmentInMem = findMemAddressOfSegment(context, ".text");
    }

    char * segmentPtr = segmentData.data();

    bool addMcountEntries = false;
    if(context.mcountEntries.size() == 0) addMcountEntries = true;
    for(uint64_t * i = mcountStart; i < mcountStop; i++)
    {
        if (addMcountEntries) context.mcountEntries.insert((*i));
        add_nops(segmentPtr + (*i) - textSegmentInMem, 5);
    }
}

void PageVerifier::applyJumpEntries(QByteArray &textSegmentContent, PageVerifier::elfParseData &context, uint64_t jumpStart, uint64_t jumpStop)
{
    //Apply the jump tables after the segments are adjacent
    //jump_label_apply_nops() => http://lxr.free-electrons.com/source/arch/x86/kernel/module.c#L205
    //the entry type is 0 for disable and 1 for enable

    bool doPrint = false;
    bool addJumpEntries = false;
    if(context.jumpEntries.size() == 0) addJumpEntries = true;

    uint32_t numberOfJumpEntries = 0;
    uint64_t textSegmentInMem = 0;

    if(context.type == Detect::KERNEL_CODE)
    {
        numberOfJumpEntries = (jumpStop - jumpStart) / sizeof(struct jump_entry);
        textSegmentInMem = context.textSegment.address;
    }
    else if(context.type == Detect::MODULE)
    {
        numberOfJumpEntries = context.currentModule.member("num_jump_entries").toUInt32();
        textSegmentInMem = findMemAddressOfSegment(context, ".text");
    }

    struct jump_entry * startEntry = (struct jump_entry *) context.jumpTable.constData();
    struct jump_entry * endEntry = (struct jump_entry *) (context.jumpTable.constData() + context.jumpTable.size());

    for(uint32_t i = 0 ; i < numberOfJumpEntries ; i++)
    {
        doPrint = false;
        //if(context.currentModule.member("name").toString().compare("\"kvm\"") == 0) doPrint = true;

        Instance jumpEntry;
        if(context.type == Detect::KERNEL_CODE)
        {
            jumpEntry = Instance((size_t) jumpStart + i * sizeof(struct jump_entry),_sym.factory().findBaseTypeByName("jump_entry"), _vmem);

            //Do not apply jump entries to .init.text
            if (jumpEntry.member("code").toUInt64() > textSegmentInMem + context.textSegment.size)
            {
                continue;
            }
        }
        else if(context.type == Detect::MODULE)
        {
            jumpEntry = context.currentModule.member("jump_entries").arrayElem(i);
        }

        uint64_t keyAddress = jumpEntry.member("key").toUInt64();

        if(doPrint) std::cout << hex << "Code: " << jumpEntry.member("code").toUInt64() << " target: " << jumpEntry.member("target").toUInt64() << dec << std::endl;
        if(doPrint) std::cout << hex << "Code offset : " << jumpEntry.member("code").toUInt64() - textSegmentInMem << " target offset : " << jumpEntry.member("target").toUInt64() - textSegmentInMem << dec << std::endl;

        Instance key = Instance((size_t) keyAddress,_sym.factory().findBaseTypeByName("static_key"), _vmem);
        uint32_t enabled = key.member("enabled").toUInt32();

        if(doPrint) std::cout << hex << "Key @ " << keyAddress << " is: " << enabled << dec << std::endl;

        for (struct jump_entry * entry = startEntry ; entry < endEntry; entry++){
            //Check if current elf entry is current kernel entry
            if (jumpEntry.member("code").toUInt64() ==  entry->code)
            {
                uint64_t patchOffset = entry->code - textSegmentInMem;

                char * patchAddress = (char *) (patchOffset + (uint64_t) textSegmentContent.data());

                if(doPrint) std::cout << "Jump Entry @ " << hex << patchOffset << dec;
                if(doPrint) std::cout << " " << ((enabled) ? "enabled" : "disabled") << std::endl;

                qint32 destination = entry->target - (entry->code + 5);
                if(addJumpEntries){
                    context.jumpEntries.insert(entry->code, destination);
                    context.jumpDestinations.insert(entry->target);
                }


                if(enabled)
                {
                    if(doPrint) std::cout << hex << "Patching jump @ : " << patchOffset << dec << std::endl;
                    *patchAddress = (char) 0xe9;
                    *((qint32*) (patchAddress + 1)) = destination;
                }
                else
                {
                    add_nops(patchAddress, 5);      //add_nops
                }
            }
        }
    }
}

void PageVerifier::applyTracepoints(SegmentInfo tracePoint, SegmentInfo rodata, PageVerifier::elfParseData &context, QByteArray &segmentData){

    //See tracepoints in kernel/tracepoint.c
    Q_UNUSED(rodata);
    Q_UNUSED(context);
    Q_UNUSED(segmentData);

    uint64_t* tracepointStart = (uint64_t*) tracePoint.index;;
    uint64_t* tracepointStop = (uint64_t*) (tracePoint.index + tracePoint.size);

    //std::cout << hex << "Start @ " << (uint64_t) tracepointStart << " Stop @ " << (uint64_t) tracepointStop << dec << std::endl;

//    uint64_t textSegmentInMem = 0;

//    if(context.type == Detect::KERNEL_CODE)
//    {
//        textSegmentInMem = context.textSegment.address;
//    }
//    else if(context.type == Detect::MODULE)
//    {
//        textSegmentInMem = findMemAddressOfSegment(context, ".text");
//    }

    //char * segmentPtr = segmentData.data();

    //qint64 dataSegmentOffset = - (uint64_t) context.dataSegment.address + (uint64_t) context.dataSegment.index;
    //qint64 rodataOffset = - (uint64_t) rodata.address + (uint64_t) rodata.index;

    uint64_t counter= 0;

    for(uint64_t* i = tracepointStart; i < tracepointStop; i++)
    {
        counter++;

        //Copy the tracepoint structure from memory
        //struct tracepoint tp;
        //_vmem->readAtomic(*i, (char*) &tp, sizeof(struct tracepoint));

        //struct tracepoint* tracepoint = (struct tracepoint*) (*i + dataSegmentOffset);

        //std::cout << " Name @ " << hex << QString(tracepoint->name + rodataOffset) <<
        //                  " enabled in ELF: " << (uint32_t) tracepoint->key.enabled <<
        //                  " enabled in Mem: " << (uint32_t) tp.key.enabled <<
        //                  " funcs @ " << (uint64_t) tp.funcs <<
        //                  std::endl;





        //add_nops(segmentPtr + (*i) - textSegmentInMem, 5);
    }

    //std::cout << "Counter is: " << counter << std::endl;
}

PageVerifier::elfParseData PageVerifier::parseKernelModule(QString fileName, Instance currentModule)
{
}

void PageVerifier::updateKernelModule(elfParseData &context)
{
    char * fileContent = context.fileContent;

    SegmentInfo info = findElfSegmentWithName(fileContent, "__mcount_loc");
    applyMcount(info, context, context.textSegmentContent);

    applyJumpEntries(context.textSegmentContent, context);

    //std::cout << "The Module got " << textSegmentContent.size() / PAGE_SIZE << " pages." << std::endl;

    // Hash
    QCryptographicHash hash(QCryptographicHash::Sha1);

    context.textSegmentData.clear();

    for(int i = 0 ; i <= context.textSegmentContent.size() / MODULE_PAGE_SIZE; i++)
    {
        PageData page = PageData();
        hash.reset();
        // Caclulate hash of one segment at the ith the offset
        QByteArray segment = context.textSegmentContent.mid(i * MODULE_PAGE_SIZE, MODULE_PAGE_SIZE);
        if (!segment.isEmpty())
        {
            segment = segment.leftJustified(MODULE_PAGE_SIZE, 0);
            page.content = segment;
            hash.addData(page.content);
            page.hash = hash.result();
            context.textSegmentData.append(page);
        }
        //std::cout << "The " << i << "th segment got a hash of: " << segmentHashes.last().toHex() << " Sections." << std::endl;
    }
}

void PageVerifier::loadElfModule(QString moduleName, Instance currentModule){


    if(!ParsedExecutables->contains(moduleName.replace(QString("-"), QString("_"))))
    {
        QString fileName = findModuleFile(moduleName);
        if(fileName == "")
        {
            debugerr("File not found for module " << moduleName);
            return;
        }

        elfParseData context = parseKernelModule(fileName, currentModule);

        ParsedExecutables->insert(moduleName.replace(QString("-"), QString("_")) , context);

        return;
    }
    elfParseData context = ParsedExecutables->value(moduleName.replace(QString("-"), QString("_")));
    uint64_t oldAddress = findMemAddressOfSegment(context, QString(".text"));

    elfParseData new_context = elfParseData(currentModule);

    uint64_t newAddress = findMemAddressOfSegment(new_context, QString(".text"));
    if (oldAddress != newAddress){
        std::cout << "Reloading module " << moduleName.replace(QString("-"), QString("_"))
                       << "\told Address 0x" << hex << oldAddress
                       << " new Address: 0x" << newAddress << dec << std::endl;
        //TODO implement this correct!!!
        if(context.fileContent != NULL){
            munmap(context.fileContent, context.fileContentSize);
        }
        fclose(context.fp);

        ParsedExecutables->remove(moduleName.replace(QString("-"), QString("_")));
        QString fileName = findModuleFile(moduleName);
        context = parseKernelModule(fileName, currentModule);

        ParsedExecutables->insert(moduleName.replace(QString("-"), QString("_")) , context);
    }

}

PageVerifier::elfParseData PageVerifier::parseKernel(QString fileName)
{
    elfParseData context = elfParseData();

    readFile(fileName, context);

    char * fileContent = context.fileContent;

    if (!context.fileContent){
        debugerr("Error loading file\n");
        return context;
    }

    context.type = Detect::KERNEL_CODE;

    context.textSegment = findElfSegmentWithName(fileContent, ".text");
    context.dataSegment = findElfSegmentWithName(fileContent, ".data");
    context.vvarSegment = findElfSegmentWithName(fileContent, ".vvar");
    context.dataNosaveSegment = findElfSegmentWithName(fileContent, ".data_nosave");
    context.bssSegment = findElfSegmentWithName(fileContent, ".bss");

    /* read the ELF header */
    Elf64_Ehdr * elf64Ehdr = (Elf64_Ehdr *) fileContent;

    /* set the file pointer to the section header offset and read it */
    Elf64_Shdr *elf64Shdr = (Elf64_Shdr *) (fileContent + elf64Ehdr->e_shoff);

    context.shstrindex = elf64Ehdr->e_shstrndx;

    /* find sections SHT_SYMTAB, SHT_STRTAB  */
    for(unsigned int i = 0; i < elf64Ehdr->e_shnum; i++)
    {
        //char *tempBuf = fileContent + elf64Shdr[elf64Ehdr->e_shstrndx].sh_offset + elf64Shdr[i].sh_name;
        if ((elf64Shdr[i].sh_type == SHT_SYMTAB)){
            context.symindex = i;
            context.strindex =  elf64Shdr[i].sh_link;
            //std::cout << "Found Symtab in Section " << i << ": " << tempBuf << std::endl << "Strtab in Section: " << elf64Shdr[i].sh_link << std::endl;
        }
    }

    //Find "__fentry__" to nop calls out later
    Elf64_Sym *symBase = (Elf64_Sym *) (fileContent + elf64Shdr[context.symindex].sh_offset);
    Elf64_Sym *sym;
    for (sym = symBase ; sym < (Elf64_Sym *) (fileContent +
                                              elf64Shdr[context.symindex].sh_offset +
                                              elf64Shdr[context.symindex].sh_size); sym++)
    {
         QString symbolName = QString(&((fileContent + elf64Shdr[context.strindex].sh_offset)[sym->st_name]));
         if(symbolName.compare(QString("__fentry__")) == 0)
         {
             context.fentryAddress = sym->st_value;
         }
         if(symbolName.compare(QString("copy_user_generic_unrolled")) == 0)
         {
             context.genericUnrolledAddress = sym->st_value;
         }
    }



    SegmentInfo info = findElfSegmentWithName(fileContent, ".altinstructions");
    if (info.index) applyAltinstr(info, context);


    info = findElfSegmentWithName(fileContent, ".parainstructions");
    if (info.index) applyParainstr(info, context);

    info = findElfSegmentWithName(fileContent, ".smp_locks");
    if (info.index) applySmpLocks(info, context);

    
    context.textSegmentContent.append(context.textSegment.index, context.textSegment.size);

    info = findElfSegmentWithName(fileContent, ".notes");
    uint64_t offset = (uint64_t) info.index - (uint64_t) context.textSegment.index;
    context.textSegmentContent = context.textSegmentContent.leftJustified(offset, 0);
    context.textSegmentContent.append(info.index, info.size);

    info = findElfSegmentWithName(fileContent, "__ex_table");
    offset = (uint64_t) info.index - (uint64_t) context.textSegment.index;
    context.textSegmentContent = context.textSegmentContent.leftJustified(offset, 0);
    context.textSegmentContent.append(info.index, info.size);


    //Apply Ftrace changes
    info = findElfSegmentWithName(fileContent, ".init.text");
    qint64 initTextOffset = - (uint64_t)info.address + (uint64_t)info.index;
    info.index = (char *)findElfAddressOfVariable(fileContent, context, "__start_mcount_loc") + initTextOffset;
    info.size = (char *)findElfAddressOfVariable(fileContent, context, "__stop_mcount_loc") + initTextOffset - info.index ;
    applyMcount(info, context, context.textSegmentContent);

    //Apply Tracepoint changes
//    SegmentInfo rodata = findElfSegmentWithName(fileContent, ".rodata");
//    qint64 rodataOffset = - (uint64_t)rodata.address + (uint64_t)rodata.index;
//    info.index = (char *)findElfAddressOfVariable(fileContent, context, "__start___tracepoints_ptrs") + rodataOffset;
//    info.size = (char *)findElfAddressOfVariable(fileContent, context, "__stop___tracepoints_ptrs") + rodataOffset - info.index ;
//    applyTracepoints(info, rodata, context, textSegmentContent);

    info = findElfSegmentWithName(fileContent, ".data");
    qint64 dataOffset = - (uint64_t)info.address + (uint64_t)info.index;
    uint64_t jumpStart = findElfAddressOfVariable(fileContent, context, "__start___jump_table");
    uint64_t jumpStop = findElfAddressOfVariable(fileContent, context, "__stop___jump_table");

    info.index = (char *)jumpStart + dataOffset;
    info.size = (char *)jumpStop + dataOffset - info.index ;

    //Save the jump_labels section for later reference.
    if(info.index != 0) context.jumpTable.append(info.index, info.size);

    applyJumpEntries(context.textSegmentContent, context, jumpStart, jumpStop);

    // Hash
    QCryptographicHash hash(QCryptographicHash::Sha1);

    for(int i = 0 ; i <= context.textSegmentContent.size() / KERNEL_CODEPAGE_SIZE; i++)
    {
        PageData page = PageData();
        hash.reset();
        // Caclulate hash of one segment at the ith the offset
        QByteArray segment = context.textSegmentContent.mid(i * KERNEL_CODEPAGE_SIZE, KERNEL_CODEPAGE_SIZE);
        if (!segment.isEmpty())
        {
            //Remember how long the contents of the text segment are,
            //this is to identify the uninitialized data
            if(segment.size() != KERNEL_CODEPAGE_SIZE)
            {
                if((segment.size()+1) % PAGE_SIZE != 0)
                {
                    uint32_t size = segment.size();
                    size += PAGE_SIZE - (size % PAGE_SIZE);
                    context.textSegmentInitialized = i * KERNEL_CODEPAGE_SIZE + size;
                }
            }
            segment = segment.leftJustified(KERNEL_CODEPAGE_SIZE, 0);
            page.content = segment;
            hash.addData(page.content);
            page.hash = hash.result();
            context.textSegmentData.append(page);
        }
        //std::cout << "The " << i << "th segment got a hash of: " << segmentHashes.last().toHex() << " Sections." << std::endl;
    }

    //TODO
    //.data
    //.vvar
    QByteArray vvarSegmentContent = QByteArray();
    vvarSegmentContent.append(context.vvarSegment.index, context.vvarSegment.size);
    for(int i = 0 ; i <= vvarSegmentContent.size() / 0x1000; i++)
    {
        PageData page = PageData();
        hash.reset();
        // Caclulate hash of one segment at the ith the offset
        QByteArray segment = vvarSegmentContent.mid(i * 0x1000, 0x1000);
        if (!segment.isEmpty())
        {
            segment = segment.leftJustified(0x1000, 0);
            page.content = segment;
            hash.addData(page.content);
            page.hash = hash.result();
            context.vvarSegmentData.append(page);
        }
    }
    //.data_nosave
    QByteArray dataNosaveSegmentContent = QByteArray();
    dataNosaveSegmentContent.append(context.vvarSegment.index, context.vvarSegment.size);
    for(int i = 0 ; i <= dataNosaveSegmentContent.size() / 0x1000; i++)
    {
        PageData page = PageData();
        hash.reset();
        // Caclulate hash of one segment at the ith the offset
        QByteArray segment = dataNosaveSegmentContent.mid(i * 0x1000, 0x1000);
        if (!segment.isEmpty())
        {
            segment = segment.leftJustified(0x1000, 0);
            page.content = segment;
            hash.addData(page.content);
            page.hash = hash.result();
            context.dataNosaveSegmentData.append(page);
        }
    }
    //.bss

    //Initialize the symTable in the context for later reference
    if(fileContent[4] == ELFCLASS32)
    {
        //TODO
    }
    else if(fileContent[4] == ELFCLASS64)
    {
        Elf64_Ehdr * elf64Ehdr = (Elf64_Ehdr *) fileContent;
        Elf64_Shdr * elf64Shdr = (Elf64_Shdr *) (fileContent + elf64Ehdr->e_shoff);

        uint32_t symSize = elf64Shdr[context.symindex].sh_size;
        Elf64_Sym *symBase = (Elf64_Sym *) (fileContent + elf64Shdr[context.symindex].sh_offset);

        for(Elf64_Sym * sym = symBase; sym < (Elf64_Sym *) (((char*) symBase) + symSize) ; sym++)
        {
            //We also need to know about private functions for data verification, so also save them here.
            //TODO fix scope
            if(ELF64_ST_TYPE(sym->st_info) & (STT_FUNC) || (ELF64_ST_TYPE(sym->st_info) == (STT_NOTYPE)))
            //if(ELF64_ST_TYPE(sym->st_info) & (STT_FUNC) || (ELF64_ST_TYPE(sym->st_info) == (STT_NOTYPE) && ELF64_ST_BIND(sym->st_info) & STB_GLOBAL))
            {
                QString symbolName = QString(&((fileContent + elf64Shdr[context.strindex].sh_offset)[sym->st_name]));
                uint64_t symbolAddress = sym->st_value;
                _funcTable.insert(symbolName, symbolAddress);
            }
            if(ELF64_ST_BIND(sym->st_info) & STB_GLOBAL )
            {
                QString symbolName = QString(&((fileContent + elf64Shdr[context.strindex].sh_offset)[sym->st_name]));
                uint64_t symbolAddress = sym->st_value;
                if(!_symTable.contains(symbolName))
                {
                    _symTable.insert(symbolName, symbolAddress);
                }
            }
        }
    }

    return context;
}

void PageVerifier::loadElfKernel(){
    if(!ParsedExecutables->contains(QString("kernel")))
    {
        elfParseData context = parseKernel(KERNEL_IMAGE);

        ParsedExecutables->insert(QString("kernel"), context);
    }
}

Instance PageVerifier::findModuleByName(QString moduleName){

    foreach (KernelModule module, this->moduleList){

        QString modNameWithoutQuotes = module.moduleName.remove(QChar('"'), Qt::CaseInsensitive);
        if(modNameWithoutQuotes.compare(moduleName) == 0 ||
                modNameWithoutQuotes.compare(moduleName.replace(QString("_"), QString("-"))) == 0 ||
                modNameWithoutQuotes.compare(moduleName.replace(QString("-"), QString("_"))) == 0)
        {
            return module.module;
        }
    }

    return Instance();
}

