#include "masternodechecker.h"
#include "masternode.h"
#include "main.h"

void CMasternodeChecker::AddMasternode(CMasterNode* mn)
{
    if(find(vPending.begin(), vPending.end(), mn) != vPending.end())
        return;

    vPending.push_back(mn);
}

void CMasternodeChecker::Reject(CMasterNode* mn)
{
    vector<CMasterNode*>::iterator it = find(vPending.begin(), vPending.end(), mn);
    if(it != vPending.end())
        vPending.erase(it);

    if(find(vRejected.begin(), vRejected.end(), mn) == vRejected.end())
        vRejected.push_back(mn);
}

CMasterNode* CMasternodeChecker::GetNextPending()
{
    if(vPending.empty())
        return NULL;

    return vPending.front();
}

void CMasternodeChecker::SendVerifyRequest(CMasterNode* mn, CNode* pnode)
{
    //create a hash of non deterministic random vars and ask mn to sign it
    CDataStream ss(SER_GETHASH, 0);
    ss << rand() << GetTime() << GetPendingCount();
    uint256 hash = Hash(ss.begin(), ss.end());

    mn->requestedHash = hash;
    pnode->PushMessage("mnprove", hash);
}

void CMasternodeChecker::Accept(CMasterNode* mn)
{
    mn->MarkValid(GetTime());
    StatusAccepted(mn);
}
