#ifndef KERNEL_ELF_PARSER_H
#define KERNEL_ELF_PARSER_H

class KernelElfParser {
	public:
		KernelElfParser();
		virtual ~KernelElfParser();
	
	private:




	
}

class KernelModule{
    Instance module;
    QString moduleName;
    uint64_t codeAddress;
    uint64_t codeSize;
};

class PageData{
    QByteArray hash;
    QByteArray content;
};

class SegmentInfo{
    SegmentInfo(): index(0), address(0), size(0) {}
    SegmentInfo(char * i, unsigned int s): index(i), address(0), size(s) {}
    SegmentInfo(char * i, uint64_t a, unsigned int s): index(i), address(a), size(s) {}

    char * index;
    uint64_t address;
    unsigned int size;
};

class elfParseData{
    elfParseData() :
        fileContent(0), type(Detect::UNDEFINED),
        symindex(0), strindex(0),
        textSegment(), dataSegment(), vvarSegment(), dataNosaveSegment(), bssSegment(),
        rodataSegment(), fentryAddress(0), genericUnrolledAddress(0),
        percpuDataSegment(0), textSegmentData(), textSegmentInitialized(0),
        vvarSegmentData(), dataNosaveSegmentData(), smpOffsets(),
        jumpTable(), textSegmentContent(), rodataContent(), currentModule(),
        jumpEntries(), jumpDestinations(), paravirtEntries(),
        mcountEntries()
    {}
    elfParseData(Instance curMod) :
        fileContent(0), type(Detect::UNDEFINED),
        symindex(0), strindex(0),
        textSegment(), dataSegment(), vvarSegment(), dataNosaveSegment(), bssSegment(),
        rodataSegment(), fentryAddress(0), genericUnrolledAddress(0),
        percpuDataSegment(0), textSegmentData(), textSegmentInitialized(0),
        vvarSegmentData(), dataNosaveSegmentData(), smpOffsets(),
        jumpTable(), textSegmentContent(), rodataContent(), currentModule(curMod),
        jumpEntries(), jumpDestinations(), paravirtEntries(),
        mcountEntries()
    {}
    ~elfParseData();


    FILE * fp;
    char * fileContent;
    long fileContentSize;
    Detect::PageType type;
    unsigned int symindex;
    unsigned int strindex;
    unsigned int shstrindex;
    SegmentInfo textSegment;
    SegmentInfo dataSegment;
    SegmentInfo vvarSegment;
    SegmentInfo dataNosaveSegment;
    SegmentInfo bssSegment;
    SegmentInfo rodataSegment;
    unsigned int relsec;
    uint64_t fentryAddress;
    uint64_t genericUnrolledAddress;
    unsigned int percpuDataSegment;
    QList<PageData> textSegmentData;
    uint32_t textSegmentInitialized;
    QList<PageData> vvarSegmentData;
    QList<PageData> dataNosaveSegmentData;
    QSet<uint64_t> smpOffsets;
    QByteArray jumpTable;
    QByteArray textSegmentContent;
    QByteArray rodataContent;
    Instance currentModule;
    QHash<uint64_t, qint32> jumpEntries;
    QSet<uint64_t> jumpDestinations;
    QSet<uint64_t> paravirtEntries;
    QSet<uint64_t> mcountEntries;

};
#endif  /* KERNEL_ELF_PARSER_H */
