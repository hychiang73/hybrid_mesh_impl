


#ifndef _MY_BASICS_HPP_INCLUDED_



//
// My_Basics.hpp is the utility of personal-development system.
//
// It will define some MACRO & TYPE, so please include me under formal header files!!!
//
// Please include me under formal header files!!!
// Please include me under formal header files!!!
// Please include me under formal header files!!!
//



//
// Other modules
//
#include "My_Basics.h"



//
// Store previous value
//
template<typename T1>
class VarLogL2{
	T1 var[2];
public:
    VarLogL2(){var[1]=0; var[0]=0;}
	void Set(T1 inVar){var[1]=var[0]; var[0]=inVar;}
	T1 Get(){return var[0];}
	T1 Get(T1 &preVar){if(preVar)preVar=var[1]; return var[0];}
	T1 GetPre(void);

	operator T1(){return var[0];}
	void operator=(T1 inT){Set(inT);}
	T1 operator++(){Set(var[0]+1); return var[0];}
	T1 operator++(int dummy){Set(var[0]+1); return var[0];}
	T1 operator+=(T1 inVar){Set(var[0]+inVar); return var[0];}
	T1 operator--(){Set(var[0]-1); return var[0];}
	T1 operator--(int dummy){Set(var[0]-1); return var[0];}
	T1 operator-=(T1 inVar){Set(var[0]-inVar); return var[0];}
};
template<typename T1>
T1 VarLogL2<T1>::GetPre(void)
{
	return var[1];
}



#define _MY_BASICS_HPP_INCLUDED_
#endif//_MY_BASICS_HPP_INCLUDED_

