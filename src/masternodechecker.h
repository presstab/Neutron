#ifndef MASTERNODECHECKER
#define MASTERNODECHECKER

#endif // MASTERNODECHECKER

#include "main.h"
#include "net.h"

using namespace std;
class CMasterNode;

class CMasternodeChecker
{
private:
    bool fSynced;
    map<CTxIn, CMasterNode*> mapAccepted;
    map<CTxIn, CMasterNode*> mapPending;
    map<CTxIn, CMasterNode*> mapRejected;
    map<CTxIn, CMasterNode*> mapTemp;

    void StatusAccepted(CMasterNode* mn)
    {
        vAccepted.push_back(mn);

        map<CTxIn, CMasterNode*>::iterator it = find(mapPending.begin(), mapPending.end(), mn);
        assert(it != mapPending.end());
        mapPending.erase(it);
    }

    bool AlreadyHave(CMasterNode* mn)
    {
        if(mapPending.count(mn.vin))
            return true;

        if(mapAccepted.count(mn.vin))
            return true;

        if(mapRejected.count(mn.vin))
            return true;

        return false;
    }

public:
    CMasternodeChecker()
    {
        fSynced = false;
        vAccepted.clear();
        mapPending.clear();
        vRejected.clear();
    }

    void AddMasternode(CMasterNode* mn);

    void Reject(CMasterNode* mn);

    void SendVerifyRequest(CMasterNode* mn, CNode* pnode);

    void Accept(CMasterNode* mn);

    int GetPendingCount()
    {
        return mapPending.size();
    }

    int GetMasternodeCount()
    {
        return mapAccepted.size() + mapPending.size();
    }

    CMasterNode* GetNextPending();
};
