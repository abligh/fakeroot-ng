#ifndef REF_COUNT_H
#define REF_COUNT_H

// Reference counting smart pointer

template <class T> class ref_count {
    struct capsule {
        T *data;
        int count;
    };

    capsule *p;

    void release()
    {
        if( p!=NULL && (--p->count)==0 ) {
            delete p->data;
            delete p;
        }

        p=NULL;
    }
public:
    ref_count<T>() : p(NULL)
    {
    }
    ref_count<T>( const ref_count<T> &rhs ) : p(rhs.p)
    {
        if( p!=NULL ) {
            p->count++;
        }
    }
    explicit ref_count<T>( T *data ) : p(new capsule)
    {
        if( p!=NULL ) {
            p->data=data;
            p->count=1;
        } else {
            // Our allocation failed, but the called relied on us to release their pointer when we're done
            delete data;
        }
    }
    ~ref_count<T>()
    {
        release();
    }

    ref_count<T> &operator=( const ref_count &rhs )
    {
        release();

        p=rhs.p;
        if( p!=NULL ) {
            p->count++;
        }

        return *this;
    }

    operator T* ()
    {
        return p!=NULL ? p->data : NULL;
    }

    operator const T*() const
    {
        return p!=NULL ? p->data : NULL;
    }

    T *operator ->()
    {
        return *this;
    }
    const T *operator ->() const
    {
        return *this;
    }

    T &operator *()
    {
        return *static_cast<T *>(*this);
    }
    const T &operator *() const
    {
        return *static_cast<const T *>(*this);
    }
};

#endif // REF_COUNT_H
